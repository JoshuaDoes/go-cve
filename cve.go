package cve

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

const (
	baseAPI = "http://cve.circl.lu/api" //Base URL of all API requests
)

type CVE struct {
	Modified                      string                    `json:"Modified"`
	Published                     string                    `json:"Published"`
	Access                        CVEAccess                 `json:"access"`
	Capec                         []CVECapec                `json:"capec"`
	CVSS                          string                    `json:"cvss"`
	CVSSTime                      string                    `json:"cvss-time"`
	CWE                           string                    `json:"cwe"`
	ExploitDB                     []ExploitDB               `json:"exploit-db"`
	ID                            string                    `json:"id"`
	Impact                        CVEImpact                 `json:"impact"`
	LastModified                  string                    `json:"last-modified"`
	Metasploit                    []Metasploit              `json:"metasploit"`
	MSBulletin                    []MSBulletin              `json:"msbulletin"`
	Nessus                        []Nessus                  `json:"nessus"`
	Oval                          []Oval                    `json:"oval"`
	PacketStorm                   []PacketStorm             `json:"packetstorm"`
	Ranking                       [][]Ranking               `json:"ranking"`
	References                    []string                  `json:"references"`
	Refmap                        Refmap                    `json:"refmap"`
	Saint                         []Saint                   `json:"saint"`
	Summary                       string                    `json:"summary"`
	TheHackerNews                 []TheHackerNews           `json:"the hacker news"`
	VulnerableConfigurations      []VulnerableConfiguration `json:"vulnerable_configuration"`
	VulnerableConfigurationsCPE22 []string                  `json:"vulnerable_configuration_cpe_2_2"`
}
type CVEAccess struct {
	Authentication string `json:"authentication"`
	Complexity     string `json:"complexity"`
	Vector         string `json:"vector"`
}
type CVECapec struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Prerequisites   string   `json:"prerequisites"`
	RelatedWeakness []string `json:"related_weakness"`
	SolutionList    string   `json:"solutions"`

	Solutions []string
}
type CVEImpact struct {
	Availability    string `json:"availability"`
	Confidentiality string `json:"confidentiality"`
	Integrity       string `json:"integrity"`
}
type ExploitDB struct {
	Description string `json:"description"`
	ID          string `json:"id"`
	LastSeen    string `json:"last seen"`
	Modified    string `json:"modified"`
	Published   string `json:"published"`
	Reporter    string `json:"reporter"`
	Source      string `json:"source"`
	Title       string `json:"title"`
}
type Metasploit struct {
	Description string `json:"description"`
	ID          string `json:"id"`
	LastSeen    string `json:"last seen"`
	Modified    string `json:"modified"`
	Published   string `json:"published"`
	Reliability string `json:"reliability"`
	Reporter    string `json:"reporter"`
	Source      string `json:"source"`
	Title       string `json:"title"`
}
type MSBulletin struct {
	BulletinID       string `json:"bulletin_id"`
	BulletinURL      string `json:"bulletin_url"`
	Date             string `json:"date"`
	Impact           string `json:"impact"`
	KnowledgeBaseID  string `json:"knowledgebase_id"`
	KnowledgeBaseURL string `json:"knowledgebase_url"`
	Severity         string `json:"severity"`
	Title            string `json:"title"`
}
type Nessus struct {
	NASLFamily  string `json:"NASL family"`
	NASLID      string `json:"NASL id"`
	Description string `json:"description"`
	LastSeen    string `json:"last seen"`
	Modified    string `json:"modified"`
	PluginID    string `json:"plugin id"`
	Published   string `json:"published"`
	Reporter    string `json:"reporter"`
	Source      string `json:"source"`
	Title       string `json:"title"`
}
type Oval struct {
	Accepted             string                    `json:"accepted"`
	Class                string                    `json:"class"`
	Contributors         []OvalContributor         `json:"contributors"`
	DefinitionExtensions []OvalDefinitionExtension `json:"definition_extensions"`
	Description          string                    `json:"description"`
	Family               string                    `json:"family"`
	ID                   string                    `json:"id"`
	Status               string                    `json:"status"`
	Submitted            string                    `json:"submitted"`
	Title                string                    `json:"title"`
	Version              string                    `json:"version"`
}
type OvalContributor struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
}
type OvalDefinitionExtension struct {
	Comment string `json:"comment"`
	Oval    string `json:"oval"`
}
type PacketStorm struct {
	DataSource string `json:"data source"`
	ID         string `json:"id"`
	LastSeen   string `json:"last seen"`
	Published  string `json:"published"`
	Reporter   string `json:"reporter"`
	Source     string `json:"source"`
	Title      string `json:"title"`
}
type Ranking struct {
	Circl int `json:"circl"`
}
type Refmap struct {
	Bid      []string `json:"bid"`
	Cert     []string `json:"cert"`
	IDefense []string `json:"idefense"`
	Sectrack []string `json:"sectrack"`
	Secunia  []string `json:"secunia"`
	SReason  []string `json:"sreason"`
	Vupen    []string `json:"vupen"`
}
type Saint struct {
	Bid         string `json:"bid"`
	Description string `json:"description"`
	ID          string `json:"id"`
	OSVDB       string `json:"osvdb"`
	Title       string `json:"title"`
	Type        string `json:"type"`
}
type TheHackerNews struct {
	ID        string `json:"id"`
	LastSeen  string `json:"last seen"`
	Modified  string `json:"modified"`
	Published string `json:"published"`
	Reporter  string `json:"reporter"`
	Source    string `json:"source"`
	Title     string `json:"title"`
}
type VulnerableConfiguration struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type Browse struct {
	Vendors []string `json:"vendor"`
}
type BrowseVendor struct {
	Products []string `json:"product"`
	Vendor   string   `json:"vendor"`
}

type SearchCVE struct {
	Modified                      string      `json:"Modified"`
	Published                     string      `json:"Published"`
	CVSS                          interface{} `json:"cvss"`
	CWE                           string      `json:"cwe"`
	ID                            string      `json:"id"`
	LastModified                  string      `json:"last-modified"`
	References                    []string    `json:"references"`
	Summary                       string      `json:"summary"`
	VulnerableConfigurations      interface{} `json:"vulnerable_configuration"`
	VulnerableConfigurationsCPE22 []string    `json:"vulnerable_configuration_cpe_2_2"`
}

func GetCVE(cveID string) (*CVE, error) {
	cveID = url.QueryEscape(cveID)

	url := baseAPI + "/cve/" + cveID

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	cve := &CVE{}

	err = unmarshal(res, cve)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len(cve.Capec); i++ {
		cve.Capec[i].Solutions = strings.Split(cve.Capec[i].SolutionList, "\n")
	}

	return cve, nil
}
func Search(vendor, product string) ([]SearchCVE, error) {
	vendor = url.QueryEscape(vendor)
	product = url.QueryEscape(product)

	url := baseAPI + "/search/" + vendor + "/" + product

	res, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	cveList := make([]SearchCVE, 0)

	err = unmarshal(res, &cveList)
	if err != nil {
		return nil, err
	}

	return cveList, nil
}

func unmarshal(body *http.Response, target interface{}) error {
	defer body.Body.Close()
	return json.NewDecoder(body.Body).Decode(target)
}
