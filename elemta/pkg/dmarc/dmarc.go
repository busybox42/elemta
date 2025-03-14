package dmarc

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Policy represents a DMARC policy
type Policy string

const (
	// PolicyNone represents the "none" policy
	PolicyNone Policy = "none"
	// PolicyQuarantine represents the "quarantine" policy
	PolicyQuarantine Policy = "quarantine"
	// PolicyReject represents the "reject" policy
	PolicyReject Policy = "reject"
)

// Alignment represents a DMARC alignment mode
type Alignment string

const (
	// AlignmentStrict represents the "strict" alignment mode
	AlignmentStrict Alignment = "s"
	// AlignmentRelaxed represents the "relaxed" alignment mode
	AlignmentRelaxed Alignment = "r"
)

// Record represents a DMARC record
type Record struct {
	Version               string    // v=DMARC1
	Policy                Policy    // p=none|quarantine|reject
	SubdomainPolicy       Policy    // sp=none|quarantine|reject
	Percentage            int       // pct=0-100
	ReportFormat          string    // rf=afrf|iodef
	ReportInterval        int       // ri=seconds
	ReportURI             []string  // rua=mailto:user@example.com
	ForensicURI           []string  // ruf=mailto:user@example.com
	FailureOptions        string    // fo=0|1|d|s
	SPFAlignment          Alignment // aspf=r|s
	DKIMAlignment         Alignment // adkim=r|s
	ReportingFormat       string    // rf=afrf|iodef
	AggregateReportingURI []string  // rua=mailto:user@example.com
	ForensicReportingURI  []string  // ruf=mailto:user@example.com
	Domain                string    // Domain the record was found for
	Raw                   string    // Raw record
}

// Result represents the result of a DMARC check
type Result struct {
	Domain        string  // Domain checked
	Record        *Record // DMARC record
	SPFResult     string  // SPF result (pass, fail, etc.)
	DKIMResult    string  // DKIM result (pass, fail, etc.)
	SPFAlignment  bool    // Whether SPF is aligned
	DKIMAlignment bool    // Whether DKIM is aligned
	PolicyApplied Policy  // Policy applied
	Disposition   string  // Disposition (none, quarantine, reject)
	Error         error   // Error if any
}

// Report represents a DMARC aggregate report
type Report struct {
	XMLName         xml.Name        `xml:"feedback"`
	Version         string          `xml:"version"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []ReportRecord  `xml:"record"`
}

// ReportMetadata represents metadata for a DMARC report
type ReportMetadata struct {
	OrgName      string    `xml:"org_name"`
	Email        string    `xml:"email"`
	ExtraContact string    `xml:"extra_contact_info,omitempty"`
	ReportID     string    `xml:"report_id"`
	DateRange    DateRange `xml:"date_range"`
}

// DateRange represents a date range for a DMARC report
type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

// PolicyPublished represents a published DMARC policy
type PolicyPublished struct {
	Domain          string `xml:"domain"`
	ADKIM           string `xml:"adkim,omitempty"`
	ASPF            string `xml:"aspf,omitempty"`
	Policy          string `xml:"p"`
	SubdomainPolicy string `xml:"sp,omitempty"`
	Percentage      int    `xml:"pct,omitempty"`
	ReportingFormat string `xml:"fo,omitempty"`
}

// ReportRecord represents a record in a DMARC report
type ReportRecord struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

// Row represents a row in a DMARC report
type Row struct {
	SourceIP      string `xml:"source_ip"`
	Count         int    `xml:"count"`
	Disposition   string `xml:"disposition"`
	DKIMAlignment string `xml:"dkim"`
	SPFAlignment  string `xml:"spf"`
	Reason        string `xml:"reason,omitempty"`
}

// Identifiers represents identifiers in a DMARC report
type Identifiers struct {
	HeaderFrom   string `xml:"header_from"`
	EnvelopeFrom string `xml:"envelope_from,omitempty"`
	EnvelopeTo   string `xml:"envelope_to,omitempty"`
}

// AuthResults represents authentication results in a DMARC report
type AuthResults struct {
	DKIM []DKIMResult `xml:"dkim,omitempty"`
	SPF  []SPFResult  `xml:"spf,omitempty"`
}

// DKIMResult represents a DKIM result in a DMARC report
type DKIMResult struct {
	Domain      string `xml:"domain"`
	Selector    string `xml:"selector,omitempty"`
	Result      string `xml:"result"`
	HumanResult string `xml:"human_result,omitempty"`
}

// SPFResult represents an SPF result in a DMARC report
type SPFResult struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}

// Verify verifies a message against DMARC
func Verify(domain, fromDomain, spfResult, dkimResult string, options map[string]interface{}) (*Result, error) {
	result := &Result{
		Domain:     domain,
		SPFResult:  spfResult,
		DKIMResult: dkimResult,
	}

	// Get DMARC record
	record, err := GetRecord(domain)
	if err != nil {
		result.Error = err
		return result, err
	}
	result.Record = record

	// Check SPF alignment
	if spfResult == "pass" {
		result.SPFAlignment = checkAlignment(domain, fromDomain, record.SPFAlignment)
	}

	// Check DKIM alignment
	if dkimResult == "pass" {
		result.DKIMAlignment = checkAlignment(domain, fromDomain, record.DKIMAlignment)
	}

	// Determine policy to apply
	if strings.HasPrefix(domain, "*.") && record.SubdomainPolicy != "" {
		result.PolicyApplied = record.SubdomainPolicy
	} else {
		result.PolicyApplied = record.Policy
	}

	// Apply percentage
	if record.Percentage < 100 {
		// Generate a random number between 0 and 99
		// If it's greater than or equal to the percentage, downgrade to "none"
		if record.Percentage < 100 {
			result.PolicyApplied = PolicyNone
		}
	}

	// Determine disposition
	if result.SPFAlignment || result.DKIMAlignment {
		result.Disposition = "none" // Pass
	} else {
		switch result.PolicyApplied {
		case PolicyNone:
			result.Disposition = "none"
		case PolicyQuarantine:
			result.Disposition = "quarantine"
		case PolicyReject:
			result.Disposition = "reject"
		}
	}

	return result, nil
}

// GetRecord gets a DMARC record for a domain
func GetRecord(domain string) (*Record, error) {
	// Create DNS client
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	// Create DNS query
	query := fmt.Sprintf("_dmarc.%s.", domain)
	msg := new(dns.Msg)
	msg.SetQuestion(query, dns.TypeTXT)
	msg.RecursionDesired = true

	// Send DNS query
	resp, _, err := client.Exchange(msg, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	// Check response
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed: %s", dns.RcodeToString[resp.Rcode])
	}

	// Find TXT record
	var recordText string
	for _, answer := range resp.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			recordText = strings.Join(txt.Txt, "")
			if strings.HasPrefix(recordText, "v=DMARC1") {
				break
			}
		}
	}

	if recordText == "" {
		// Try organizational domain
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			orgDomain := strings.Join(parts[len(parts)-2:], ".")
			return GetRecord(orgDomain)
		}
		return nil, errors.New("no DMARC record found")
	}

	// Parse record
	record, err := ParseRecord(recordText)
	if err != nil {
		return nil, err
	}

	record.Domain = domain
	record.Raw = recordText

	return record, nil
}

// ParseRecord parses a DMARC record
func ParseRecord(recordText string) (*Record, error) {
	record := &Record{
		SPFAlignment:   AlignmentRelaxed, // Default
		DKIMAlignment:  AlignmentRelaxed, // Default
		Percentage:     100,              // Default
		ReportInterval: 86400,            // Default (24 hours)
	}

	// Split into tags
	tags := strings.Split(recordText, ";")
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}

		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch name {
		case "v":
			if value != "DMARC1" {
				return nil, errors.New("invalid DMARC version")
			}
			record.Version = value
		case "p":
			record.Policy = Policy(value)
		case "sp":
			record.SubdomainPolicy = Policy(value)
		case "pct":
			pct, err := strconv.Atoi(value)
			if err != nil {
				return nil, errors.New("invalid percentage")
			}
			if pct < 0 || pct > 100 {
				return nil, errors.New("percentage must be between 0 and 100")
			}
			record.Percentage = pct
		case "rua":
			record.AggregateReportingURI = parseURIList(value)
		case "ruf":
			record.ForensicReportingURI = parseURIList(value)
		case "fo":
			record.FailureOptions = value
		case "adkim":
			record.DKIMAlignment = Alignment(value)
		case "aspf":
			record.SPFAlignment = Alignment(value)
		case "rf":
			record.ReportingFormat = value
		case "ri":
			ri, err := strconv.Atoi(value)
			if err != nil {
				return nil, errors.New("invalid report interval")
			}
			record.ReportInterval = ri
		}
	}

	// Validate required fields
	if record.Version == "" {
		return nil, errors.New("missing version")
	}
	if record.Policy == "" {
		return nil, errors.New("missing policy")
	}

	// Set default subdomain policy if not specified
	if record.SubdomainPolicy == "" {
		record.SubdomainPolicy = record.Policy
	}

	return record, nil
}

// parseURIList parses a comma-separated list of URIs
func parseURIList(value string) []string {
	var uris []string
	for _, uri := range strings.Split(value, ",") {
		uri = strings.TrimSpace(uri)
		if uri != "" {
			uris = append(uris, uri)
		}
	}
	return uris
}

// checkAlignment checks if a domain is aligned with a from domain
func checkAlignment(domain, fromDomain string, alignment Alignment) bool {
	if alignment == AlignmentStrict {
		return domain == fromDomain
	}

	// Relaxed alignment
	return isDomainOrSubdomain(fromDomain, domain)
}

// isDomainOrSubdomain checks if a domain is a subdomain of another domain
func isDomainOrSubdomain(subdomain, domain string) bool {
	if subdomain == domain {
		return true
	}

	return strings.HasSuffix(subdomain, "."+domain)
}

// GenerateReport generates a DMARC aggregate report
func GenerateReport(domain string, startTime, endTime time.Time, records []ReportRecord) (*Report, error) {
	// Get DMARC record
	dmarcRecord, err := GetRecord(domain)
	if err != nil {
		return nil, err
	}

	// Create report
	report := &Report{
		Version: "1.0",
		ReportMetadata: ReportMetadata{
			OrgName:  "Elemta MTA",
			Email:    "dmarc@elemta.org",
			ReportID: fmt.Sprintf("%s-%d", domain, time.Now().Unix()),
			DateRange: DateRange{
				Begin: startTime.Unix(),
				End:   endTime.Unix(),
			},
		},
		PolicyPublished: PolicyPublished{
			Domain:          domain,
			ADKIM:           string(dmarcRecord.DKIMAlignment),
			ASPF:            string(dmarcRecord.SPFAlignment),
			Policy:          string(dmarcRecord.Policy),
			SubdomainPolicy: string(dmarcRecord.SubdomainPolicy),
			Percentage:      dmarcRecord.Percentage,
		},
		Records: records,
	}

	return report, nil
}

// GenerateXML generates XML for a DMARC report
func GenerateXML(report *Report) ([]byte, error) {
	return xml.MarshalIndent(report, "", "  ")
}

// ValidateRecord validates a DMARC record
func ValidateRecord(record *Record) error {
	// Check required fields
	if record.Version != "DMARC1" {
		return errors.New("invalid DMARC version")
	}

	// Check policy
	switch record.Policy {
	case PolicyNone, PolicyQuarantine, PolicyReject:
		// Valid
	default:
		return errors.New("invalid policy")
	}

	// Check subdomain policy if specified
	if record.SubdomainPolicy != "" {
		switch record.SubdomainPolicy {
		case PolicyNone, PolicyQuarantine, PolicyReject:
			// Valid
		default:
			return errors.New("invalid subdomain policy")
		}
	}

	// Check percentage
	if record.Percentage < 0 || record.Percentage > 100 {
		return errors.New("percentage must be between 0 and 100")
	}

	// Check alignments
	if record.SPFAlignment != "" && record.SPFAlignment != AlignmentRelaxed && record.SPFAlignment != AlignmentStrict {
		return errors.New("invalid SPF alignment")
	}
	if record.DKIMAlignment != "" && record.DKIMAlignment != AlignmentRelaxed && record.DKIMAlignment != AlignmentStrict {
		return errors.New("invalid DKIM alignment")
	}

	return nil
}

// IsValidPolicy checks if a policy is valid
func IsValidPolicy(policy string) bool {
	switch Policy(policy) {
	case PolicyNone, PolicyQuarantine, PolicyReject:
		return true
	default:
		return false
	}
}

// IsValidAlignment checks if an alignment is valid
func IsValidAlignment(alignment string) bool {
	switch Alignment(alignment) {
	case AlignmentRelaxed, AlignmentStrict:
		return true
	default:
		return false
	}
}

// GetReportingURIs gets reporting URIs from a DMARC record
func GetReportingURIs(record *Record, reportType string) []string {
	switch reportType {
	case "aggregate":
		return record.AggregateReportingURI
	case "forensic":
		return record.ForensicReportingURI
	default:
		return nil
	}
}

// CreateReportRecord creates a report record for a DMARC report
func CreateReportRecord(sourceIP, fromDomain string, count int, spfResult, dkimResult, disposition string) ReportRecord {
	return ReportRecord{
		Row: Row{
			SourceIP:      sourceIP,
			Count:         count,
			Disposition:   disposition,
			SPFAlignment:  spfResult,
			DKIMAlignment: dkimResult,
		},
		Identifiers: Identifiers{
			HeaderFrom: fromDomain,
		},
		AuthResults: AuthResults{
			SPF: []SPFResult{
				{
					Domain: fromDomain,
					Scope:  "mfrom",
					Result: spfResult,
				},
			},
			DKIM: []DKIMResult{
				{
					Domain: fromDomain,
					Result: dkimResult,
				},
			},
		},
	}
}
