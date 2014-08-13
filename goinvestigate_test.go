package goinvestigate

import (
	"flag"
	"log"
	"os"
	"testing"
)

var (
	key string
	inv *Investigate
)

func init() {
	verbose := flag.Bool("sgverbose", false, "Set SGraph output to verbose.")
	flag.Parse()
	key := os.Getenv("INVESTIGATE_KEY")
	if key == "" {
		log.Fatal("INVESTIGATE_KEY environment variable not set")
	}
	inv = New(key)
	inv.SetVerbose(*verbose)
}

func TestRRHistory(t *testing.T) {
	// test an IP
	outMap, err := inv.RRHistory("208.64.121.161", "A")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"features", "rrs"}, t)

	// test a domain
	outMap, err = inv.RRHistory("www.test.com", "A")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"features", "rrs_tf"}, t)

	// trying an unsupported query type should return an error
	outMap, err = inv.RRHistory("www.test.com", "AFSDB")
	if outMap != nil || err == nil {
		t.Fatal("Querying the wrong query type did not return an error.")
	}
}

func TestCategorization(t *testing.T) {
	catKeys := []string{"status", "content_categories", "security_categories"}

	// test a single domain
	outMap, err := inv.Categorization("www.amazon.com", false)

	if err != nil {
		t.Fatal(err)
	}

	hasKeys(outMap, []string{"www.amazon.com"}, t)
	hasKeys(outMap["www.amazon.com"].(map[string]interface{}), catKeys, t)

	// test a list of domains with labels
	domains := []string{"www.amazon.com", "www.opendns.com", "bibikun.ru"}
	outMap, err = inv.Categorization(domains, true)

	if err != nil {
		t.Fatal(err)
	}

	hasKeys(outMap, domains, t)

	for _, domain := range domains {
		hasKeys(outMap[domain].(map[string]interface{}), catKeys, t)
	}
}

//func TestGetIps(t *testing.T) {
//ips := []string{
//"208.64.121.161",
//"108.59.1.5",
//"37.205.198.162",
//"176.215.86.120",
//"203.121.165.16",
//"211.151.57.196",
//"109.123.83.130",
//"141.101.117.230",
//"119.17.168.4",
//"119.57.72.26",
//}
//resultsChan := inv.GetIps(ips)
//for result := range resultsChan {
//hasKeys(result, []string{"features", "rrs"}, t)
//}
//}

//func TestGetDomains(t *testing.T) {
//domains := []string{
//"www.test.com",
//"bibikun.ru",
//"0zu1.de",
//"0tqcsp1a.emltrk.com",
//"1000conversions.com",
//"10safetytips.com",
//"adelur.org",
//"admin.adventurelanding.com",
//"arabstoday.com",
//"arbokeuringen.nl",
//}
//resultsChan := inv.GetDomains(domains)
//for result := range resultsChan {
//hasKeys(result, []string{"features", "rrs_tf"}, t)
//}
//}

func TestRelatedDomains(t *testing.T) {
	outMap, err := inv.RelatedDomains("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"found", "tb1"}, t)
}

//func TestGetRelatedDomainses(t *testing.T) {
//// need a bigger list of known domains
//domains := []string{
//"www.test.com",
//}
//resultsChan := inv.GetRelatedDomainses(domains)
//for result := range resultsChan {
//hasKeys(result, []string{"found", "tb1"}, t)
//}
//}

func TestScore(t *testing.T) {
	outMap, err := inv.Score("bibikun.ru")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"confidence", "label", "name", "path", "score", "z"}, t)
}

//func TestGetScores(t *testing.T) {
//// need a list of more domains that have scores
//domains := []string{
//"bibikun.ru",
//}
//resultsChan := inv.GetScores(domains)
//for result := range resultsChan {
//hasKeys(result, []string{"confidence", "label", "name", "path", "score", "z"}, t)
//}
//}

func TestCooccurrences(t *testing.T) {
	outMap, err := inv.Cooccurrences("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"found", "pfs2"}, t)
}

//func TestGetCooccurrenceses(t *testing.T) {
//// need a bigger list
//domains := []string{
//"www.test.com",
//}
//resultsChan := inv.GetCooccurrenceses(domains)
//for result := range resultsChan {
//hasKeys(result, []string{"found", "pfs2"}, t)
//}
//}

func TestSecurity(t *testing.T) {
	outMap, err := inv.Security("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{
		"dga_score",
		"perplexity",
		"entropy",
		"securerank2",
		"pagerank",
		"asn_score",
		"prefix_score",
		"rip_score",
		"fastflux",
		"popularity",
		"geodiversity",
		"geodiversity_normalized",
		"tld_geodiversity",
		"geoscore",
		"ks_test",
		"handlings",
		"attack",
		"threat_type",
		"found",
	}
	hasKeys(outMap, keys, t)
}

//func TestGetSecurities(t *testing.T) {
//domains := []string{
//"www.test.com",
//"bibikun.ru",
//"0zu1.de",
//"0tqcsp1a.emltrk.com",
//"1000conversions.com",
//"10safetytips.com",
//"adelur.org",
//}
//resultsChan := inv.GetSecurities(domains)
//for result := range resultsChan {
//hasKeys(result, []string{"asn_score", "crank", "dga_score", "entropy",
//"fastflux", "found", "frequencyrank", "geodiversity", "geodiversity_normalized",
//"geoscore", "handlings", "ks_test", "pagerank", "perplexity", "popularity",
//"prefix_score", "rip_score", "securerank", "securerank2", "tags", "tld_geodiversity"}, t)
//}
//}

func hasKeys(data map[string]interface{}, keys []string, t *testing.T) {
	for _, key := range keys {
		if _, ok := data[key]; !ok {
			t.Errorf("data is missing key: %v\ndata: %v\n", key, data)
			t.Fail()
		}
	}
}
