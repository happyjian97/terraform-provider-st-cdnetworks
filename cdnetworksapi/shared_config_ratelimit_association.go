package cdnetworksapi

import (
	"net/http"
)

// AssociateSharedRateLimitRule
type AssociateSharedRateLimitRuleRequest struct {
	ShareID    string   `json:"shareId"`
	DomainList []string `json:"domainList"`
}

type AssociateSharedRateLimitRuleResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func (c *Client) AssociateSharedRateLimitRule(serviceType string, request *AssociateSharedRateLimitRuleRequest) (response *AssociateSharedRateLimitRuleResponse, err error) {
	header := make(http.Header)
	if serviceType != "" {
		header.Set("serviceType", serviceType)
	}

	_, err = c.DoJsonApiRequest(Request{
		Method: HttpPost,
		Path:   "/api/v1/common/share-rate-limit/associate",
		Header: header,
		Body:   request,
	}, &response)

	return
}

// DisassociateSharedRateLimitRule
type DisassociateSharedRateLimitRuleRequest struct {
	ShareID    string   `json:"shareId"`
	DomainList []string `json:"domainList"`
}

type DisassociateSharedRateLimitRuleResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func (c *Client) DisassociateSharedRateLimitRule(serviceType string, request *DisassociateSharedRateLimitRuleRequest) (response *DisassociateSharedRateLimitRuleResponse, err error) {
	header := make(http.Header)
	if serviceType != "" {
		header.Set("serviceType", serviceType)
	}

	_, err = c.DoJsonApiRequest(Request{
		Method: HttpPost,
		Path:   "/api/v1/common/share-rate-limit/disassociate",
		Header: header,
		Body:   request,
	}, &response)

	return
}
