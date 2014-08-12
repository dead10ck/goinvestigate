/*
API for the OpenDNS Security Graph / Investigate.

To use it, use your Investigate API keys, which should be in their own .pem files,
to build an SGraph object.

	sg, err := sgraph.New(certFile, keyFile)

	if err != nil {
		log.Fatal(err)
	}

Then you can call any API method, e.g.:
	data, err := sg.GetDomain("www.test.com")
which returns the map:
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
	resultsChan := sg.GetIps(ips)
	for result := range resultsChan {
		// do something with result
	}
However, any requests which return an error are discarded. If this is not desireable,
it is necessary to implement concurrency in your application.

Be sure to set runtime.GOMAXPROCS() in the init() function of your program to enable
concurrency.
*/
package sgraph

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/dchest/siphash"
)

const (
	sgraphUri  = "https://sgraph.umbrella.com"
	siphashKey = "Umbrella/OpenDNS"
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

type SGraph struct {
	client    *http.Client
	log       *log.Logger
	sipHasher hash.Hash64
	verbose   bool
}

// Build a new SGraph client using certFile and keyFile.
// If there is an error, returns a nil *SGraph and the error.
// Otherwise, returns a new *SGraph client and a nil error.
func New(certFile, keyFile string) (*SGraph, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error building the SGraph client: %v\n", err))
	}

	tc := &tls.Config{Certificates: []tls.Certificate{cert}}
	sg := &SGraph{
		&http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tc,
			},
		},
		log.New(os.Stdout, `[SGraph] `, 0),
		siphash.New([]byte(siphashKey)),
		false,
	}

	return sg, nil
}

// A generic Request method which makes the given request
func (sg *SGraph) Request(req *http.Request) (*http.Response, error) {
	resp := new(http.Response)
	var err error
	tries := 0

	for ; resp.Body == nil && tries < maxTries; tries++ {
		sg.Logf("%s %s\n", req.Method, req.URL.String())
		resp, err = sg.client.Do(req)
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

// A generic GET call to the SGraph API. Will make an HTTP request to: https://sgraph.umbrella.com{subUri}
func (sg *SGraph) Get(subUri string) (*http.Response, error) {
	req, err := http.NewRequest("GET", sgraphUri+subUri, nil)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error processing GET request: %v", err))
	}

	return sg.Request(req)
}

// A generic POST call, which forms a request with the given body
func (sg *SGraph) Post(subUri string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", sgraphUri+subUri, body)

	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error processing POST request: %v", err))
	}

	return sg.Request(req)
}

// Use ip to make the HTTP request: /dnsdb/ip/a/{ip}.json
func (sg *SGraph) GetIp(ip string) (map[string]interface{}, error) {
	return sg.GetParse(fmt.Sprintf(urls["ip"], ip))
}

// Call GetIp() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
func (sg *SGraph) GetIps(ips []string) <-chan map[string]interface{} {
	subUris := convertToSubUris(ips, "ip")
	return sg.pGetParse(subUris)
}

// Use domain to make the HTTP request: /dnsdb/name/a/{domain}.json
func (sg *SGraph) GetDomain(domain string) (map[string]interface{}, error) {
	return sg.GetParse(fmt.Sprintf(urls["domain"], domain))
}

// Call GetDomain() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
func (sg *SGraph) GetDomains(domains []string) <-chan map[string]interface{} {
	subUris := convertToSubUris(domains, "domain")
	return sg.pGetParse(subUris)
}

// Use domain to make the HTTP request: /links/name/{domain}.json
func (sg *SGraph) GetRelatedDomains(domain string) (map[string]interface{}, error) {
	return sg.GetParse(fmt.Sprintf(urls["related"], domain))
}

// Call GetRelatedDomains() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
// Sorry about the awkward name. Some of these already had plural names.
func (sg *SGraph) GetRelatedDomainses(domains []string) <-chan map[string]interface{} {
	subUris := convertToSubUris(domains, "related")
	return sg.pGetParse(subUris)
}

// Use domain to make the HTTP request: /label/rface-gbt/name/{domain}.json
func (sg *SGraph) GetScore(domain string) (map[string]interface{}, error) {
	return sg.GetParse(fmt.Sprintf(urls["score"], domain))
}

// Call GetScore() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
func (sg *SGraph) GetScores(domains []string) <-chan map[string]interface{} {
	subUris := convertToSubUris(domains, "score")
	return sg.pGetParse(subUris)
}

// Use domain to make the HTTP request: /recommendations/name/{domain}.json
func (sg *SGraph) GetCooccurrences(domain string) (map[string]interface{}, error) {
	return sg.GetParse(fmt.Sprintf(urls["cooccurrences"], domain))
}

// Call GetCooccurrences() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
// Sorry about the awkward name. Some of these already had plural names.
func (sg *SGraph) GetCooccurrenceses(domains []string) <-chan map[string]interface{} {
	subUris := convertToSubUris(domains, "cooccurrences")
	return sg.pGetParse(subUris)
}

// Use domain to make the HTTP request: /security/name/{domain}.json
func (sg *SGraph) GetSecurity(domain string) (map[string]interface{}, error) {
	return sg.GetParse(fmt.Sprintf(urls["security"], domain))
}

// Call GetSecurity() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
func (sg *SGraph) GetSecurities(domains []string) <-chan map[string]interface{} {
	subUris := convertToSubUris(domains, "security")
	return sg.pGetParse(subUris)
}

// Use domain to make the HTTP request: /whois/name/{domain}.json
func (sg *SGraph) GetWhois(domain string) (map[string]interface{}, error) {
	return sg.GetParse(fmt.Sprintf(urls["whois"], domain))
}

// Call GetGetWhois() on the given list of domains. All requests are made
// concurrently in the number of goroutines specified by "SetMaxGoroutines."
// Defaults to 10. Returns the channel through which output will be sent.
func (sg *SGraph) GetWhoises(domains []string) <-chan map[string]interface{} {
	subUris := convertToSubUris(domains, "whois")
	return sg.pGetParse(subUris)
}

// Query the infected status of the given slice of URLs
func (sg *SGraph) GetInfected(infectedUrls []string) (map[string]interface{}, error) {
	urlsJson, err := json.Marshal(infectedUrls)

	if err != nil {
		sg.Log(err.Error())
		return nil, err
	}

	body := bytes.NewReader(urlsJson)
	subUri := fmt.Sprintf(urls["infected"], sg.SipHash(urlsJson))
	return sg.PostParse(subUri, body)
}

func (sg *SGraph) GetTraffic(domain string, start, stop time.Time) (map[string]interface{}, error) {
	startUriEnc := start.Format(timeLayout)
	stopUriEnc := stop.Format(timeLayout)

	uriQueries := url.Values{}
	uriQueries.Set("start", startUriEnc)
	uriQueries.Set("stop", stopUriEnc)

	// need this literal string because apparently changing the order of the
	// parameters breaks the server [..] <- that's the sound of me rolling my eyes
	subUri := fmt.Sprintf("/appserver/?v=1&function=domain2-system&domains=%s&locations=&%s",
		domain, uriQueries.Encode())

	return sg.GetParse(subUri)
}

// Returns the SipHash of the given byte slice b, encoded with the public
// key "Umbrella/OpenDNS", as a hex-encoded string
func (sg *SGraph) SipHash(b []byte) string {
	sg.sipHasher.Reset()
	sg.sipHasher.Write(b)
	sum := sg.sipHasher.Sum64()
	return strconv.FormatUint(sum, 16)
}

// Converts the given list of items (domains or IPs)
// to a list of their appropriate URIs for the SGraph API
func convertToSubUris(items []string, queryType string) []string {
	subUris := make([]string, len(items))
	for i, item := range items {
		subUris[i] = fmt.Sprintf(urls[queryType], item)
	}
	return subUris
}

// convenience function to perform Get and parse the response body
func (sg *SGraph) GetParse(subUri string) (map[string]interface{}, error) {
	resp, err := sg.Get(subUri)

	if err != nil {
		sg.Log(err.Error())
		return nil, err
	}

	body, err := parseBody(resp.Body)

	if err != nil && sg.verbose {
		sg.Log(err.Error())
	}

	return body, err
}

// worker goroutine for parallel GetParse
func (sg *SGraph) doPGetParse(inChan chan string, outChan chan map[string]interface{}, done chan int) {
	for uri := range inChan {
		outVal, err := sg.GetParse(uri)
		if err != nil {
			outChan <- outVal
		}
	}
	done <- 1
}

// parallelized getparse.
func (sg *SGraph) pGetParse(subUris []string) <-chan map[string]interface{} {
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
		go sg.doPGetParse(inChan, outChan, done)
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
func (sg *SGraph) PostParse(subUri string, body io.Reader) (map[string]interface{}, error) {
	resp, err := sg.Post(subUri, body)

	if err != nil {
		sg.Log(err.Error())
		return nil, err
	}

	respBody, err := parseBody(resp.Body)

	if err != nil {
		sg.Log(err.Error())
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
func (sg *SGraph) Log(s string) {
	if sg.verbose {
		sg.log.Println(s)
	}
}

// Log something to stdout with a format string
func (sg *SGraph) Logf(fs string, args ...interface{}) {
	if sg.verbose {
		sg.log.Printf(fs, args...)
	}
}

// Sets verbose messages to the given boolean value.
func (sg *SGraph) SetVerbose(verbose bool) {
	sg.verbose = verbose
}

// Sets the maximum number of goroutines to run bulk requests
// Default is 10
func (sg *SGraph) SetMaxGoroutines(n int) {
	maxGoroutines = n
}
