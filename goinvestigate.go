/*
API for the OpenDNS Security Graph / Investigate.

To use it, use your Investigate API key to build an Investigate object.

	inv, err := goinvestigate.New(certFile, keyFile)

	if err != nil {
		log.Fatal(err)
	}

Then you can call any API method, e.g.:
	data, err := inv.RRHistory("www.test.com")
which returns the map:
	UPDATE ME
	map[	rrs_tf:[map[first_seen:2014-02-18 last_seen:2014-05-20
			rrs:[map[name:www.test.com. ttl:3600 class:IN type:CNAME rr:test.blockdos.com.]]]]
		features:map[cname:true base_domain:test.com]
	]

Most API methods also come with a sibling method that acts on lists of input, and
it will do them concurrently. For instance, you can call GetIp() on a list of IPs
by using GetIps(). It will call GetIp() on every domain in the input list concurrently.
	ips := []string{
		"208.64.121.161",
		"108.59.1.5",
		"37.205.198.162",
		"176.215.86.120",
		"203.121.165.16",
		"211.151.57.196",
		"109.123.83.130",
		"141.101.117.230",
		"119.17.168.4",
		"119.57.72.26",
	}
	resultsChan := inv.GetIps(ips)
	for result := range resultsChan {
		// do something with result
	}
However, any requests which return an error are discarded. If this is not desireable,
it is necessary to implement concurrency in your application.

Be sure to set runtime.GOMAXPROCS() in the init() function of your program to enable
concurrency.
*/
package goinvestigate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

const (
	baseUrl    = "https://investigate.api.opendns.com"
	maxTries   = 5
	timeLayout = "2006/01/02/15"
)

// format strings for API URIs
var urls map[string]string = map[string]string{
	"ip":             "/dnsdb/ip/%s/%s.json",
	"domain":         "/dnsdb/name/%s/%s.json",
	"categorization": "/domains/categorization/%s",
	"related":        "/links/name/%s.json",
	"cooccurrences":  "/recommendations/name/%s.json",
	"security":       "/security/name/%s.json",
	"tags":           "/domains/%s/latest_tags",
}

var supportedQueryTypes map[string]int = map[string]int{
	"A":     1,
	"NS":    1,
	"MX":    1,
	"TXT":   1,
	"CNAME": 1,
}

type Investigate struct {
	client  *http.Client
	key     string
	log     *log.Logger
	verbose bool
}

// Build a new Investigate client using certFile and keyFile.
// If there is an error, returns a nil *Investigate and the error.
// Otherwise, returns a new *Investigate client and a nil error.
func New(key string) *Investigate {
	return &Investigate{
		&http.Client{},
		key,
		log.New(os.Stdout, `[Investigate] `, 0),
		false,
	}
}

// A generic Request method which makes the given request
func (inv *Investigate) Request(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", inv.key))
	resp := new(http.Response)
	var err error
	tries := 0

	for ; resp.Body == nil && tries < maxTries; tries++ {
		inv.Logf("%s %s\n", req.Method, req.URL.String())
		resp, err = inv.client.Do(req)
		if err != nil {
			if tries == maxTries-1 {
				return nil,
					errors.New(fmt.Sprintf("error: %v\nFailed all attempts. Skipping.", err))
			}
			log.Printf("\nerror: %v\nTrying again: Attempt %d/%d\n", err, tries+1, maxTries)
			resp = new(http.Response)
		}
	}

	return resp, err
}

// A generic GET call to the Investigate API.
// Will make an HTTP request to: https://investigate.api.opendns.com{subUri}
func (inv *Investigate) Get(subUri string) (*http.Response, error) {
	req, err := http.NewRequest("GET", baseUrl+subUri, nil)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error processing GET request: %v", err))
	}

	return inv.Request(req)
}

// A generic POST call, which forms a request with the given body
func (inv *Investigate) Post(subUri string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", baseUrl+subUri, body)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error processing POST request: %v", err))
	}

	return inv.Request(req)
}

// Get the domain status and categorization of a domain or list of domains.
// 'domains' can be either a single domain, or a list of domains.
// Setting 'labels' to true will give back categorizations in human-readable form.
//
// For more detail, see https://sgraph.opendns.com/docs/api#categorization
func (inv *Investigate) Categorization(domains interface{}, labels bool) (interface{}, error) {
	switch d := domains.(type) {
	case string:
		return inv.getCategorization(d, labels)
	case []string:
		return inv.postCategorization(d, labels)
	default:
		return nil, errors.New(
			"domains must be either a string, or a list of strings")
	}
}

func catUri(domain string, labels bool) string {
	uri, err := url.Parse(fmt.Sprintf(urls["categorization"], domain))

	if err != nil {
		log.Fatal(err)
	}

	v := url.Values{}

	if labels {
		v.Set("showLabels", "true")
	}

	uri.RawQuery = v.Encode()
	return uri.String()
}

func (inv *Investigate) getCategorization(domain string, labels bool) (interface{}, error) {
	uri := catUri(domain, labels)
	return inv.GetParse(uri)
}

func (inv *Investigate) postCategorization(domains []string, labels bool) (interface{}, error) {
	uri := fmt.Sprintf(urls["categorization"], "")
	body, err := json.Marshal(domains)

	if err != nil {
		inv.Logf("Error marshalling domain slice into JSON: %v", err)
		return nil, err
	}

	return inv.PostParse(uri, bytes.NewReader(body))
}

// Use domain to make the HTTP request: /links/name/{domain}.json
// Get the related domains of the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#relatedDomains
func (inv *Investigate) RelatedDomains(domain string) (interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["related"], domain))
}

// Get the cooccurrences of the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#co-occurrences
func (inv *Investigate) Cooccurrences(domain string) (interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["cooccurrences"], domain))
}

// Get the Security Information for the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#securityInfo
func (inv *Investigate) Security(domain string) (interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["security"], domain))
}

// Get the domain tagging dates for the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#latest_tags
func (inv *Investigate) DomainTags(domain string) (respJson interface{}, err error) {
	return inv.GetParse(fmt.Sprintf(urls["tags"], domain))
}

// Get the RR (Resource Record) History of the given domain or IP, given by query.
// The following query types are supported:
//
// A, NS, MX, TXT, CNAME
//
// For details, see https://sgraph.opendns.com/docs/api#dnsrr_domain
func (inv *Investigate) RRHistory(query string, queryType string) (interface{}, error) {
	// If the user tried an unsupported query type, return an error
	if _, ok := supportedQueryTypes[queryType]; !ok {
		return nil, errors.New("unsupported query type")
	}
	// if this is an IP, do an IP query
	if match, err := regexp.MatchString(`(\d{1,3}\.){3}\d{1,3}`, query); match {
		return inv.ipRRHistory(query, queryType)
	} else if err != nil {
		return nil, err
	}

	// otherwise, do a domain query
	return inv.domainRRHistory(query, queryType)

}

// Use ip to make the HTTP request: /dnsdb/ip/a/{ip}.json
func (inv *Investigate) ipRRHistory(ip string, queryType string) (interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["ip"], queryType, ip))
}

// Use domain to make the HTTP request: /dnsdb/name/a/{domain}.json
func (inv *Investigate) domainRRHistory(domain string, queryType string) (interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["domain"], queryType, domain))
}

// Converts the given list of items (domains or IPs)
// to a list of their appropriate URIs for the Investigate API
func convertToSubUris(items []string, queryType string) []string {
	subUris := make([]string, len(items))
	for i, item := range items {
		subUris[i] = fmt.Sprintf(urls[queryType], item)
	}
	return subUris
}

// convenience function to perform Get and parse the response body
func (inv *Investigate) GetParse(subUri string) (interface{}, error) {
	resp, err := inv.Get(subUri)

	if err != nil {
		inv.Log(err.Error())
		return nil, err
	}

	body, err := parseBody(resp.Body)

	if err != nil && inv.verbose {
		inv.Log(err.Error())
	}

	return body, err
}

//convenience function to perform Post and parse the response body
func (inv *Investigate) PostParse(subUri string, body io.Reader) (interface{}, error) {
	resp, err := inv.Post(subUri, body)

	if err != nil {
		inv.Log(err.Error())
		return nil, err
	}

	respBody, err := parseBody(resp.Body)

	if err != nil {
		inv.Log(err.Error())
	}

	return respBody, err
}

// Parse an HTTP JSON response into a map
func parseBody(respBody io.ReadCloser) (respJson interface{}, err error) {
	defer respBody.Close()
	d := json.NewDecoder(respBody)
	err = d.Decode(&respJson)
	return respJson, err
}

// Log something to stdout
func (inv *Investigate) Log(s string) {
	if inv.verbose {
		inv.log.Println(s)
	}
}

// Log something to stdout with a format string
func (inv *Investigate) Logf(fs string, args ...interface{}) {
	if inv.verbose {
		inv.log.Printf(fs, args...)
	}
}

// Sets verbose messages to the given boolean value.
func (inv *Investigate) SetVerbose(verbose bool) {
	inv.verbose = verbose
}
