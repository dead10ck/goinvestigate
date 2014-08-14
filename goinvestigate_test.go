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

func TestRelatedDomains(t *testing.T) {
	outMap, err := inv.RelatedDomains("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"found", "tb1"}, t)
}

func TestCooccurrences(t *testing.T) {
	outMap, err := inv.Cooccurrences("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	hasKeys(outMap, []string{"found", "pfs2"}, t)
}

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

func hasKeys(data map[string]interface{}, keys []string, t *testing.T) {
	for _, key := range keys {
		if _, ok := data[key]; !ok {
			t.Errorf("data is missing key: %v\ndata: %v\n", key, data)
			t.Fail()
		}
	}
}
