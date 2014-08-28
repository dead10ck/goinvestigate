/*
API for the OpenDNS Security Graph / Investigate.

To use it, use your Investigate API key to build an Investigate object.

	key := "f29be9cc-f833-4a9a-b984-19dc4d5186ac"
	inv, err := goinvestigate.New(key)

	if err != nil {
		log.Fatal(err)
	}

Then you can call any API method, e.g.:
	data, err := inv.DomainRRHistory("www.test.com")
which returns a DomainRRHistory object.

Be sure to set runtime.GOMAXPROCS() in the init() function of your program to enable
concurrency.

The official OpenDNS Investigate Documentation can be found at:
https://sgraph.opendns.com/docs/api
*/
package goinvestigate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
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
	"latest_domains": "/ips/%s/latest_domains",
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

// Build a new Investigate client using an Investigate API key.
func New(key string) *Investigate {
	return &Investigate{
		&http.Client{},
		key,
		log.New(os.Stdout, `[Investigate] `, 0),
		false,
	}
}

// A generic Request method which makes the given request.
// Will retry up to 5 times on failure.
func (inv *Investigate) Request(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", inv.key))
	resp := new(http.Response)
	var err error
	tries := 0

	for ; resp.Body == nil && tries < maxTries; tries++ {
		inv.Logf("%s %s\n", req.Method, req.URL.String())
		resp, err = inv.client.Do(req)
		if err != nil || resp.StatusCode >= 300 {
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

// Get the domain status and categorization of a domain.
// Setting 'labels' to true will give back categorizations in human-readable form.
//
// For more detail, see https://sgraph.opendns.com/docs/api#categorization
func (inv *Investigate) Categorization(domain string, labels bool) (*DomainCategorization, error) {
	uri := catUri(domain, labels)
	resp := make(map[string]DomainCategorization)
	err := inv.GetParse(uri, resp)
	if err != nil {
		return nil, err
	}
	if cat, ok := resp[domain]; !ok {
		return nil, errors.New("received a malformed response body")
	} else {
		return &cat, nil
	}
}

// Get the status and categorization of a list of domains
// Setting 'labels' to true will give back categorizations in human-readable form.
//
// For more detail, see https://sgraph.opendns.com/docs/api#categorization
func (inv *Investigate) Categorizations(domains []string, labels bool) (map[string]DomainCategorization, error) {
	uri := catUri("", labels)
	body, err := json.Marshal(domains)

	if err != nil {
		inv.Logf("Error marshalling domain slice into JSON: %v", err)
		return nil, err
	}

	resp := make(map[string]DomainCategorization)
	err = inv.PostParse(uri, bytes.NewReader(body), resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Use domain to make the HTTP request: /links/name/{domain}.json
// Get the related domains of the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#relatedDomains
func (inv *Investigate) RelatedDomains(domain string) ([]RelatedDomain, error) {
	var resp RelatedDomainList
	err := inv.GetParse(fmt.Sprintf(urls["related"], domain), &resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Get the cooccurrences of the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#co-occurrences
func (inv *Investigate) Cooccurrences(domain string) ([]Cooccurrence, error) {
	var resp CooccurrenceList
	err := inv.GetParse(fmt.Sprintf(urls["cooccurrences"], domain), &resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Get the Security Information for the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#securityInfo
func (inv *Investigate) Security(domain string) (*SecurityFeatures, error) {
	resp := new(SecurityFeatures)
	err := inv.GetParse(fmt.Sprintf(urls["security"], domain), resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Get the domain tagging dates for the given domain.
//
// For details, see https://sgraph.opendns.com/docs/api#latest_tags
func (inv *Investigate) DomainTags(domain string) ([]DomainTag, error) {
	var resp []DomainTag
	err := inv.GetParse(fmt.Sprintf(urls["tags"], domain), &resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func queryTypeSupported(qType string) bool {
	_, ok := supportedQueryTypes[qType]
	return ok
}

// Get the RR (Resource Record) History of the given IP.
// queryType is the type of DNS query to perform on the database.
// The following query types are supported:
//
// A, NS, MX, TXT, CNAME
//
// For details, see https://sgraph.opendns.com/docs/api#dnsrr_ip
func (inv *Investigate) IpRRHistory(ip string, queryType string) (*IPRRHistory, error) {
	// If the user tried an unsupported query type, return an error
	if !queryTypeSupported(queryType) {
		return nil, errors.New("unsupported query type")
	}
	resp := new(IPRRHistory)
	err := inv.GetParse(fmt.Sprintf(urls["ip"], queryType, ip), resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Get the RR (Resource Record) History of the given domain.
// queryType is the type of DNS query to perform on the database.
// The following query types are supported:
//
// A, NS, MX, TXT, CNAME
//
// For details, see https://sgraph.opendns.com/docs/api#dnsrr_domain
func (inv *Investigate) DomainRRHistory(domain string, queryType string) (*DomainRRHistory, error) {
	// If the user tried an unsupported query type, return an error
	if !queryTypeSupported(queryType) {
		return nil, errors.New("unsupported query type")
	}
	resp := new(DomainRRHistory)
	err := inv.GetParse(fmt.Sprintf(urls["domain"], queryType, domain), resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func extractDomains(respList []MaliciousDomain) []string {
	var domainList []string
	for _, entry := range respList {
		domainList = append(domainList, entry.Domain)
	}
	return domainList
}

// Gets the latest known malicious domains associated with the given
// IP address, if any. Returns the list of malicious domains.
//
// For details, see https://sgraph.opendns.com/docs/api#latest_domains
func (inv *Investigate) LatestDomains(ip string) ([]string, error) {
	var resp []MaliciousDomain
	err := inv.GetParse(fmt.Sprintf(urls["latest_domains"], ip), &resp)

	if err != nil {
		return nil, err
	}

	return extractDomains(resp), nil
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

// Convenience function to perform Get and parse the response body.
// Parses the response into the value pointed to by v.
func (inv *Investigate) GetParse(subUri string, v interface{}) error {
	resp, err := inv.Get(subUri)

	if err != nil {
		inv.Log(err.Error())
		return err
	}

	err = parseBody(resp.Body, v)

	if err != nil && inv.verbose {
		inv.Log(err.Error())
	}

	return err
}

// Convenience function to perform Post and parse the response body.
// Parses the response into the value pointed to by v.
func (inv *Investigate) PostParse(subUri string, body io.Reader, v interface{}) error {
	resp, err := inv.Post(subUri, body)

	if err != nil {
		inv.Log(err.Error())
		return err
	}

	err = parseBody(resp.Body, v)

	if err != nil {
		inv.Log(err.Error())
	}

	return err
}

type JSONDecodeError struct {
	Err  error
	Body []byte
}

func (e JSONDecodeError) Error() string {
	return fmt.Sprintf("error: %s\nbody: %s", e.Err.Error(), e.Body)
}

// Parse an HTTP JSON response into a map
func parseBody(respBody io.ReadCloser, v interface{}) (err error) {
	defer respBody.Close()
	d := json.NewDecoder(respBody)
	switch unpackedValue := v.(type) {
	case *CooccurrenceList:
		err = d.Decode(unpackedValue)
	case *RelatedDomainList:
		err = d.Decode(unpackedValue)
	case *[]MaliciousDomain:
		err = d.Decode(unpackedValue)
	case map[string]DomainCategorization:
		err = d.Decode(&unpackedValue)
	case *SecurityFeatures:
		err = d.Decode(unpackedValue)
	case *[]DomainTag:
		err = d.Decode(unpackedValue)
	case *DomainRRHistory:
		err = d.Decode(unpackedValue)
	case *IPRRHistory:
		err = d.Decode(unpackedValue)
	default:
		err = errors.New("type of v is unsupported")
	}
	//return err
	if err != nil {
		body, readErr := ioutil.ReadAll(respBody)
		if readErr != nil {
			log.Printf("error reading body: %v", readErr)
			return err
		}
		return JSONDecodeError{Err: err, Body: body}
	}
	return err
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
