package cdnetworksapi

import "net/http"

// Overall RateLimitRule response
type RateLimitRule struct {
	ID                        string                  `json:"id"`
	Creator                   string                  `json:"creator"`
	RuleName                  string                  `json:"ruleName"`
	Description               string                  `json:"description"`
	StatisticalStage          string                  `json:"statisticalStage"`
	StatisticalItems          []StatisticalItem       `json:"statisticalItems"`
	StatisticalPeriod         int                     `json:"statisticalPeriod"`
	TriggerThreshold          int                     `json:"triggerThreshold"`
	InterceptTime             int                     `json:"interceptTime"`
	EffectiveStatus           string                  `json:"effectiveStatus"`
	RateLimitEffective        *RateLimitEffective     `json:"rateLimitEffective"`
	Action                    string                  `json:"action"`
	RateLimitRuleCondition    *RateLimitRuleCondition `json:"rateLimitRuleCondition"`
	CountShareRateLimitDomain int                     `json:"countShareRateLimitDomain"`
	ShareRateLimitRelDomains  []string                `json:"shareRateLimitRelDomains"`
	UpdateTime                string                  `json:"updateTime"`
	RedirectURL               string                  `json:"redirectUrl"`
}

// StatisticalItem is one entry of the statisticalItems list.
type StatisticalItem struct {
	StatisticalItem string   `json:"statisticalItem"`
	StatisticsKeys  []string `json:"statisticsKeys,omitempty"`
}

// RateLimitEffective represents the rule's effective time period.
type RateLimitEffective struct {
	Effective []string `json:"effective"`
	Start     string   `json:"start"`
	End       string   `json:"end"`
	Timezone  string   `json:"timezone"`
}

// RateLimitRuleCondition contains all supported matching conditions. All
// condition lists are optional, unset conditions are omitted from the
// request body.
type RateLimitRuleCondition struct {
	IPOrIPsConditions    []IPOrIPsCondition    `json:"ipOrIpsConditions,omitempty"`
	PathConditions       []PathCondition       `json:"pathConditions,omitempty"`
	URIConditions        []URICondition        `json:"uriConditions,omitempty"`
	UAConditions         []UACondition         `json:"uaConditions,omitempty"`
	MethodConditions     []MethodCondition     `json:"methodConditions,omitempty"`
	RefererConditions    []RefererCondition    `json:"refererConditions,omitempty"`
	HeaderConditions     []HeaderCondition     `json:"headerConditions,omitempty"`
	AreaConditions       []AreaCondition       `json:"areaConditions,omitempty"`
	SchemeConditions     []SchemeCondition     `json:"schemeConditions,omitempty"`
	StatusCodeConditions []StatusCodeCondition `json:"statusCodeConditions,omitempty"`
	JA3Conditions        []JA3Condition        `json:"ja3Conditions,omitempty"`
	JA4Conditions        []JA4Condition        `json:"ja4Conditions,omitempty"`
	ASNConditions        []ASNCondition        `json:"asnConditions,omitempty"`
}

// IP/CIDR matching.
type IPOrIPsCondition struct {
	MatchType string   `json:"matchType"`
	IPOrIPs   []string `json:"ipOrIps"`
}

// Path matching.
type PathCondition struct {
	MatchType string   `json:"matchType"`
	Paths     []string `json:"paths"`
}

// URI matching.
type URICondition struct {
	MatchType string   `json:"matchType"`
	URI       []string `json:"uri"`
}

// User-Agent matching.
type UACondition struct {
	MatchType string   `json:"matchType"`
	UA        []string `json:"ua"`
}

// HTTP request method matching.
type MethodCondition struct {
	MatchType     string   `json:"matchType"`
	RequestMethod []string `json:"requestMethod"`
}

// Referer matching.
type RefererCondition struct {
	MatchType string   `json:"matchType"`
	Referer   []string `json:"referer"`
}

// Request header matching.
type HeaderCondition struct {
	MatchType        string   `json:"matchType"`
	ValueList        []string `json:"valueList"`
	Key              string   `json:"key"`
	KeyMatchWildcard string   `json:"keyMatchWildcard,omitempty"`
}

// Geographic matching.
type AreaCondition struct {
	MatchType string   `json:"matchType"`
	Areas     []string `json:"areas"`
}

// HTTP/HTTPS scheme matching.
type SchemeCondition struct {
	MatchType string   `json:"matchType"`
	Scheme    []string `json:"scheme"`
}

// HTTP response status code matching.
type StatusCodeCondition struct {
	MatchType  string   `json:"matchType"`
	StatusCode []string `json:"statusCode"`
}

// JA3 fingerprint matching.
type JA3Condition struct {
	MatchType string   `json:"matchType"`
	JA3List   []string `json:"ja3List"`
}

// JA4 fingerprint matching.
type JA4Condition struct {
	MatchType string   `json:"matchType"`
	JA4List   []string `json:"ja4List"`
}

// Autonomous System Number matching.
type ASNCondition struct {
	MatchType string   `json:"matchType"`
	ASNList   []uint32 `json:"asnList"`
}

// GetSharedRateLimitRules
type GetSharedRateLimitRulesRequest struct {
	RuleName string `json:"ruleName,omitempty"`
}

type GetSharedRateLimitRulesResponse struct {
	Code string          `json:"code"`
	Msg  string          `json:"msg"`
	Data []RateLimitRule `json:"data"`
}

func (c *Client) GetSharedRateLimitRules(request *GetSharedRateLimitRulesRequest) (response *GetSharedRateLimitRulesResponse, err error) {
	_, err = c.DoJsonApiRequest(Request{
		Method: HttpPost,
		Path:   "/api/v2/share-rate-limit/get-rule-list",
		Body:   request,
	}, &response)

	return
}

// AddSharedRateLimitRule
type AddSharedRateLimitRuleRequest struct {
	RuleName               string                  `json:"ruleName"`
	Description            string                  `json:"description,omitempty"`
	StatisticalItems       []StatisticalItem       `json:"statisticalItems"`
	StatisticalPeriod      int                     `json:"statisticalPeriod"`
	TriggerThreshold       int                     `json:"triggerThreshold"`
	InterceptTime          int                     `json:"interceptTime"`
	EffectiveStatus        string                  `json:"effectiveStatus"`
	RateLimitEffective     *RateLimitEffective     `json:"rateLimitEffective,omitempty"`
	Action                 string                  `json:"action"`
	RateLimitRuleCondition *RateLimitRuleCondition `json:"rateLimitRuleCondition"`
	RedirectURL            string                  `json:"redirectUrl,omitempty"`
}

type AddSharedRateLimitRuleResponse struct {
	Code string `json:"code"`
	Msg  string `json:"msg"`
	Data string `json:"data"`
}

func (c *Client) AddSharedRateLimitRule(serviceType string, request *AddSharedRateLimitRuleRequest) (response *AddSharedRateLimitRuleResponse, err error) {
	header := make(http.Header)
	if serviceType != "" {
		header.Set("serviceType", serviceType)
	}

	_, err = c.DoJsonApiRequest(Request{
		Method: HttpPost,
		Path:   "/api/v2/share-rate-limit/add-rule",
		Header: header,
		Body:   request,
	}, &response)

	return
}
