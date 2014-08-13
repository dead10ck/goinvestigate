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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const (
	baseUrl    = "https://investigate.api.opendns.com"
	maxTries   = 5
	timeLayout = "2006/01/02/15"
)

var maxGoroutines int = 10

// format strings for API URIs
var urls map[string]string = map[string]string{
	"ip":            "/dnsdb/ip/a/%s.json",
	"domain":        "/dnsdb/name/a/%s.json",
	"related":       "/links/name/%s.json",
	"score":         "/label/rface-gbt/name/%s.json",
	"cooccurrences": "/recommendations/name/%s.json",
	"security":      "/security/name/%s.json",
	"whois":         "/whois/name/%s.json",
	"infected":      "/infected/names/%s.json",
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

// A generic GET call to the Investigate API. Will make an HTTP request to: https://invraph.umbrella.com{subUri}
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

// Use domain to make the HTTP request: /links/name/{domain}.json
func (inv *Investigate) GetRelatedDomains(domain string) (map[string]interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["related"], domain))
}

// Call GetRelatedDomains() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
// Sorry about the awkward name. Some of these already had plural names.
//func (inv *Investigate) GetRelatedDomainses(domains []string) <-chan map[string]interface{} {
//subUris := convertToSubUris(domains, "related")
//return inv.pGetParse(subUris)
//}

// Use domain to make the HTTP request: /label/rface-gbt/name/{domain}.json
func (inv *Investigate) GetScore(domain string) (map[string]interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["score"], domain))
}

// Call GetScore() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
//func (inv *Investigate) GetScores(domains []string) <-chan map[string]interface{} {
//subUris := convertToSubUris(domains, "score")
//return inv.pGetParse(subUris)
//}

// Use domain to make the HTTP request: /recommendations/name/{domain}.json
func (inv *Investigate) GetCooccurrences(domain string) (map[string]interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["cooccurrences"], domain))
}

// Call GetCooccurrences() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
// Sorry about the awkward name. Some of these already had plural names.
//func (inv *Investigate) GetCooccurrenceses(domains []string) <-chan map[string]interface{} {
//subUris := convertToSubUris(domains, "cooccurrences")
//return inv.pGetParse(subUris)
//}

// Use domain to make the HTTP request: /security/name/{domain}.json
func (inv *Investigate) GetSecurity(domain string) (map[string]interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["security"], domain))
}

// Call GetSecurity() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
//func (inv *Investigate) GetSecurities(domains []string) <-chan map[string]interface{} {
//subUris := convertToSubUris(domains, "security")
//return inv.pGetParse(subUris)
//}

// Use ip to make the HTTP request: /dnsdb/ip/a/{ip}.json
func (inv *Investigate) GetIp(ip string) (map[string]interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["ip"], ip))
}

// Call GetIp() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
//func (inv *Investigate) GetIps(ips []string) <-chan map[string]interface{} {
//subUris := convertToSubUris(ips, "ip")
//return inv.pGetParse(subUris)
//}

// Use domain to make the HTTP request: /dnsdb/name/a/{domain}.json
func (inv *Investigate) GetDomain(domain string) (map[string]interface{}, error) {
	return inv.GetParse(fmt.Sprintf(urls["domain"], domain))
}

// Call GetDomain() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
//func (inv *Investigate) GetDomains(domains []string) <-chan map[string]interface{} {
//subUris := convertToSubUris(domains, "domain")
//return inv.pGetParse(subUris)
//}

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
func (inv *Investigate) GetParse(subUri string) (map[string]interface{}, error) {
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

// worker goroutine for parallel GetParse
func (inv *Investigate) doPGetParse(inChan chan string, outChan chan map[string]interface{}, done chan int) {
	for uri := range inChan {
		outVal, err := inv.GetParse(uri)
		if err != nil {
			outChan <- outVal
		}
	}
	done <- 1
}

// parallelized getparse.
func (inv *Investigate) pGetParse(subUris []string) <-chan map[string]interface{} {
	outChan := make(chan map[string]interface{}, len(subUris))
	inChan := make(chan string, len(subUris))
	done := make(chan int, maxGoroutines)

	// populate the input channel with the provided list
	go func() {
		for _, uri := range subUris {
			inChan <- uri
		}
		close(inChan)
	}()

	// launch the workers
	for i := 0; i < maxGoroutines; i++ {
		go inv.doPGetParse(inChan, outChan, done)
	}

	// launch a single goroutine which waits for all the goroutines to finish
	go func() {
		for i := 0; i < maxGoroutines; i++ {
			<-done
		}
		// once they are all finished, close the output channel
		close(outChan)
	}()

	return outChan
}

//convenience function to perform Post and parse the response body
func (inv *Investigate) PostParse(subUri string, body io.Reader) (map[string]interface{}, error) {
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
func parseBody(respBody io.ReadCloser) (respJson map[string]interface{}, err error) {
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

// Sets the maximum number of goroutines to run bulk requests
// Default is 10
func (inv *Investigate) SetMaxGoroutines(n int) {
	maxGoroutines = n
}
