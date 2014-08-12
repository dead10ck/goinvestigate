package sgraph

import (
	"flag"
	"log"
	"testing"
	"time"
)

var (
	keyFile, certFile string
	sg                *SGraph
)

func init() {
	flag.StringVar(&keyFile, "key", "", "Output matching IPs to the given file (REQUIRED)")
	flag.StringVar(&certFile, "cert", "", "Output matching IPs to the given file (REQUIRED)")
	verbose := flag.Bool("sgverbose", false, "Set SGraph output to verbose.")
	flag.Parse()

	if keyFile == "" || certFile == "" {
		log.Fatal("Need cert and key file.")
	}

	var err error
	sg, err = New(certFile, keyFile)

	if err != nil {
		log.Fatalf("Error building SGraph client: %v\n", err)
	}

	sg.SetVerbose(*verbose)
}

func TestGetIp(t *testing.T) {
	outMap, err := sg.GetIp("208.64.121.161")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"features", "rrs"}, t)
}

func TestGetIps(t *testing.T) {
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
		hasKeys(result, []string{"features", "rrs"}, t)
	}
}

func TestGetDomain(t *testing.T) {
	outMap, err := sg.GetDomain("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"features", "rrs_tf"}, t)
}

func TestGetDomains(t *testing.T) {
	domains := []string{
		"www.test.com",
		"bibikun.ru",
		"0zu1.de",
		"0tqcsp1a.emltrk.com",
		"1000conversions.com",
		"10safetytips.com",
		"adelur.org",
		"admin.adventurelanding.com",
		"arabstoday.com",
		"arbokeuringen.nl",
	}
	resultsChan := sg.GetDomains(domains)
	for result := range resultsChan {
		hasKeys(result, []string{"features", "rrs_tf"}, t)
	}
}

func TestGetRelatedDomains(t *testing.T) {
	outMap, err := sg.GetRelatedDomains("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"found", "tb1"}, t)
}

func TestGetRelatedDomainses(t *testing.T) {
	// need a bigger list of known domains
	domains := []string{
		"www.test.com",
	}
	resultsChan := sg.GetRelatedDomainses(domains)
	for result := range resultsChan {
		hasKeys(result, []string{"found", "tb1"}, t)
	}
}

func TestGetScore(t *testing.T) {
	outMap, err := sg.GetScore("bibikun.ru")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"confidence", "label", "name", "path", "score", "z"}, t)
}

func TestGetScores(t *testing.T) {
	// need a list of more domains that have scores
	domains := []string{
		"bibikun.ru",
	}
	resultsChan := sg.GetScores(domains)
	for result := range resultsChan {
		hasKeys(result, []string{"confidence", "label", "name", "path", "score", "z"}, t)
	}
}

func TestGetCooccurrences(t *testing.T) {
	outMap, err := sg.GetCooccurrences("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"found", "pfs2"}, t)
}

func TestGetCooccurrenceses(t *testing.T) {
	// need a bigger list
	domains := []string{
		"www.test.com",
	}
	resultsChan := sg.GetCooccurrenceses(domains)
	for result := range resultsChan {
		hasKeys(result, []string{"found", "pfs2"}, t)
	}
}

func TestGetSecurity(t *testing.T) {
	outMap, err := sg.GetSecurity("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"asn_score", "crank", "dga_score", "entropy",
		"fastflux", "found", "frequencyrank", "geodiversity", "geodiversity_normalized",
		"geoscore", "handlings", "ks_test", "pagerank", "perplexity", "popularity",
		"prefix_score", "rip_score", "securerank", "securerank2", "tags", "tld_geodiversity"}, t)
}

func TestGetSecurities(t *testing.T) {
	domains := []string{
		"www.test.com",
		"bibikun.ru",
		"0zu1.de",
		"0tqcsp1a.emltrk.com",
		"1000conversions.com",
		"10safetytips.com",
		"adelur.org",
	}
	resultsChan := sg.GetSecurities(domains)
	for result := range resultsChan {
		hasKeys(result, []string{"asn_score", "crank", "dga_score", "entropy",
			"fastflux", "found", "frequencyrank", "geodiversity", "geodiversity_normalized",
			"geoscore", "handlings", "ks_test", "pagerank", "perplexity", "popularity",
			"prefix_score", "rip_score", "securerank", "securerank2", "tags", "tld_geodiversity"}, t)
	}
}

func TestGetWhois(t *testing.T) {
	outMap, err := sg.GetWhois("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"found"}, t)
}

func TestGetWhoises(t *testing.T) {
	domains := []string{
		"www.test.com",
		"bibikun.ru",
		"0zu1.de",
		"0tqcsp1a.emltrk.com",
		"1000conversions.com",
		"10safetytips.com",
		"adelur.org",
		"admin.adventurelanding.com",
		"arabstoday.com",
		"arbokeuringen.nl",
	}
	resultsChan := sg.GetWhoises(domains)
	for result := range resultsChan {
		hasKeys(result, []string{"found"}, t)
	}
}

func TestGetInfected(t *testing.T) {
	outMap, err := sg.GetInfected([]string{"www.test.com", "bibikun.ru"})
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"scores"}, t)
	scores := outMap["scores"].(map[string]interface{})
	hasKeys(scores, []string{"www.test.com", "bibikun.ru"}, t)

	// do again to make sure the sipHasher resets correctly
	outMap, err = sg.GetInfected([]string{"www.test.com", "bibikun.ru"})
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"scores"}, t)
	scores = outMap["scores"].(map[string]interface{})
	hasKeys(scores, []string{"www.test.com", "bibikun.ru"}, t)
}

func TestGetTraffic(t *testing.T) {
	loc, err := time.LoadLocation("Local")
	if err != nil {
		log.Fatal("Failed to load location: %v", err)
	}
	outMap, err := sg.GetTraffic("wikileaks.org", time.Date(2013, 12, 13, 0, 0, 0, 0, loc), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"elapsed", "function", "query", "response"}, t)
}

func hasKeys(data map[string]interface{}, keys []string, t *testing.T) {
	for _, key := range keys {
		if _, ok := data[key]; !ok {
			t.Errorf("data is missing key: %v\ndata: %v\n", key, data)
			t.Fail()
		}
	}
}
