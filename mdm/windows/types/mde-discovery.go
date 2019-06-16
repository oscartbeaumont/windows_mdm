package windowstype

import (
	"io"
	"errors"
	"strings"
	"encoding/xml"
)

var ( // TODO: Clean Error Messages
	ErrEmptyEmailAddress = errors.New("invalid email address not set")
	ErrNoAuthPolicies = errors.New("invalid no auth policies are set")
)

type MdeDiscoveryRequest struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"` // Attribute xmlns:a & xmlns:s not implemented
	Header  struct {
		Action    string `xml:"http://www.w3.org/2005/08/addressing Action"` // Attribute s:mustUnderstand not implemented
		MessageID string `xml:"http://www.w3.org/2005/08/addressing MessageID"`
		ReplyTo   struct {
			Address string `xml:"http://www.w3.org/2005/08/addressing Address"`
		} `xml:"http://www.w3.org/2005/08/addressing ReplyTo"`
		To URL `xml:"http://www.w3.org/2005/08/addressing To"` // Attribute s:mustUnderstand not implemented
	} `xml:"http://www.w3.org/2003/05/soap-envelope Header"`
	Body struct {
		Discover struct {
			Request struct { // Attribute xmlns:i not implemented
				EmailAddress       string `xml:"EmailAddress"`
				RequestVersion     string `xml:"RequestVersion"`
				DeviceType         string `xml:"DeviceType"`
				ApplicationVersion string `xml:"ApplicationVersion"`
				OSEdition          string `xml:"OSEdition"`
				AuthPolicies       []string `xml:"AuthPolicies"`
			} `xml:"request"`
		} `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment Discover"`
	} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
}

func (cmd *MdeDiscoveryRequest) Decode(b io.ReadCloser) error {
	return xml.NewDecoder(b).Decode(cmd)
}

func (cmd MdeDiscoveryRequest) Verify() error {
	if cmd.Header.Action != "http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/Discover" {
		return ErrInvalidAction
	}

	domain := strings.Split(cmd.Header.To.Host, ":")
	if len(domain) > 2 || len(domain) == 0 || domain[0] == "" {
		return ErrEmptyToDomain
	}

	if cmd.Header.To.Path != "/EnrollmentServer/Discovery.svc" {
		return ErrInvalidToPath
	}

	if cmd.Header.MessageID == "" {
		return ErrEmptyMessageID
	}

	if cmd.Header.ReplyTo.Address == "" {
		return ErrEmptyReplyToAddress
	}

	if cmd.Body.Discover.Request.EmailAddress == "" {
		return ErrEmptyEmailAddress
	}
	
	if len(cmd.Body.Discover.Request.AuthPolicies) == 0 {
		return ErrNoAuthPolicies
	}

	return nil
}

type MdeDiscoveryResponse struct {
	AuthPolicy                 string `xml:"DiscoverResult>AuthPolicy"`
	EnrollmentPolicyServiceURL string `xml:"DiscoverResult>EnrollmentPolicyServiceUrl,omitempty"`
	EnrollmentServiceURL       string `xml:"DiscoverResult>EnrollmentServiceUrl"`
	AuthenticationServiceUrl   string `xml:"DiscoverResult>AuthenticationServiceUrl,omitempty"`
	EnrollmentVersion          string `xml:"DiscoverResult>EnrollmentVersion,omitempty"`
}