package goinvestigate

import (
	"encoding/json"
	"errors"
	"fmt"
)

type DomainCategorization struct {
	Status             int
	ContentCategories  []string `json:"content_categories"`
	SecurityCategories []string `json:"security_categories"`
}

type Cooccurrence struct {
	Domain string
	Score  float64
}

type CooccurrenceList struct {
	Cooccurrences []Cooccurrence `json:"pfs2"`
}

func (r *CooccurrenceList) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	cl := new(CooccurrenceList)
	err := json.Unmarshal(b, &raw)

	if err != nil {
		return err
	}

	malfErr := errors.New(fmt.Sprintf("malformed object: %v", raw))
	coocs, ok := raw["pfs2"].([]interface{})

	if !ok {
		return malfErr
	}

	for _, c := range coocs {
		if double, ok := c.([]interface{}); !ok {
			return malfErr
		} else {
			var d string
			var s float64
			d, ok := double[0].(string)
			if !ok {
				return malfErr
			}
			s, ok = double[1].(float64)
			if !ok {
				return malfErr
			}
			cl.Cooccurrences = append(cl.Cooccurrences, Cooccurrence{
				Domain: d,
				Score:  s,
			})
		}
	}

	*r = *cl
	return nil
}

type RelatedDomain struct {
	Domain string
	Score  int
}

type RelatedDomainList struct {
	RelatedDomains []RelatedDomain `json:"tb1"`
}

func (r *RelatedDomainList) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	rl := new(RelatedDomainList)
	err := json.Unmarshal(b, &raw)

	if err != nil {
		return err
	}

	malfErr := errors.New(fmt.Sprintf("malformed object: %v", raw))
	rds, ok := raw["tb1"].([]interface{})

	if !ok {
		return malfErr
	}

	for _, r := range rds {
		if double, ok := r.([]interface{}); !ok {
			return malfErr
		} else {
			var d string
			var s float64
			d, ok := double[0].(string)
			if !ok {
				return errors.New("Could not convert double[0] to string")
			}
			s, ok = double[1].(float64)
			if !ok {
				return errors.New("Could not convert double[1] to int")
			}
			rl.RelatedDomains = append(rl.RelatedDomains, RelatedDomain{
				Domain: d,
				Score:  int(s),
			})
		}
	}

	*r = *rl
	return nil
}

type GeoFeatures struct {
	CountryCode string
	VisitRatio  float64
}

func (gf *GeoFeatures) UnmarshalJSON(b []byte) error {
	finalGf := new(GeoFeatures)
	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	malfErr := errors.New(fmt.Sprintf("malformed object: %v", raw))

	gfList, ok := raw.([]interface{})
	if !ok {
		return malfErr
	}

	if cc, ok := gfList[0].(string); !ok {
		return malfErr
	} else {
		finalGf.CountryCode = cc
	}

	if vr, ok := gfList[1].(float64); !ok {
		return malfErr
	} else {
		finalGf.VisitRatio = vr
	}

	*gf = *finalGf
	return nil
}

type SecurityFeatures struct {
	DGAScore               float64 `json:"dga_score"`
	Perplexity             float64
	Entropy                float64
	SecureRank2            float64 `json:"securerank2"`
	PageRank               float64 `json:"pagerank"`
	ASNScore               float64 `json:"asn_score"`
	PrefixScore            float64 `json:"prefix_score"`
	RIPScore               float64 `json:"rip_score"`
	Fastflux               bool
	Popularity             float64
	Geodiversity           []GeoFeatures `json:"geodiversity"`
	GeodiversityNormalized []GeoFeatures `json:"geodiversity_normalized"`
	TLDGeodiversity        []GeoFeatures `json:"tld_geodiversity"`
	Geoscore               float64
	KSTest                 float64 `json:"ks_test"`
	Handlings              string
	Attack                 string
	ThreatType             string `json:"threat_type"`
}

type PeriodType struct {
	Begin string
	End   string
}

type DomainTag struct {
	Url      string
	Category string
	Period   PeriodType
}

type ResourceRecord struct {
	Name  string
	TTL   int
	Class string
	Type  string
	RR    string
}

type ResourceRecordPeriod struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	RRs       []ResourceRecord
}

type Location struct {
	Lat float64
	Lon float64
}

type DomainResourceRecordFeatures struct {
	Age             int
	TTLsMin         int      `json:"ttls_min"`
	TTLsMax         int      `json:"ttls_max"`
	TTLsMean        int      `json:"ttls_mean"`
	TTLsMedian      int      `json:"ttls_median"`
	TTLsStdDev      int      `json:"ttls_stddev"`
	CountryCodes    []string `json:"country_codes"`
	ASNs            []int
	Prefixes        []string
	RIPSCount       int     `json:"rips"`
	RIPSDiversity   float64 `json:"div_rips"`
	Locations       []Location
	GeoDistanceSum  float64 `json:"geo_distance_sum"`
	GeoDistanceMean float64 `json:"geo_distance_mean"`
	NonRoutable     bool    `json:"non_routable"`
	MailExchanger   bool    `json:"mail_exchanger"`
	CName           bool
	FFCandidate     bool    `json:"ff_candidate"`
	RIPSStability   float64 `json:"rips_stability"`
}

type DomainRRHistory struct {
	RRPeriods  []ResourceRecordPeriod       `json:"rrs_tf"`
	RRFeatures DomainResourceRecordFeatures `json:"features"`
}

type IPResourceRecordFeatures struct {
	RRCount   int     `json:"rr_count"`
	LD2Count  int     `json:"ld2_count"`
	LD3Count  int     `json:"ld3_count"`
	LD21Count int     `json:"ld2_1_count"`
	LD22Count int     `json:"ld2_2_count"`
	DivLD2    float64 `json:"div_ld2"`
	DivLD3    float64 `json:"div_ld3"`
	DivLD21   float64 `json:"div_ld2_1"`
	DivLD22   float64 `json:"div_ld2_2"`
}

type IPRRHistory struct {
	RRs        []ResourceRecord
	RRFeatures IPResourceRecordFeatures `json:"features"`
}

type MaliciousDomain struct {
	Domain string `json:"name"`
	Id     int
}
