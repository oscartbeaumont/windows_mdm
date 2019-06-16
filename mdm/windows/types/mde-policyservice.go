package windowstype

import (
	"errors"
	"strings"
	"encoding/xml"
	"io"
)

var ( // TODO: Clean Error Messages
	ErrEmptyUsername = errors.New("empty username")
	ErrInvalidUsernameToken = errors.New("invalid username token")
	ErrEmptyPassword = errors.New("empty password")
	ErrInvalidPasswordType = errors.New("invalid password type")
)

type MdePolicyServiceRequest struct {
	XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"` // Attribute xmlns:a, xmlns:s, xmlns:u, xmlns:wsse, xmlns:wst & xmlns:ac not implemented
	Header  struct {
		Action    string `xml:"http://www.w3.org/2005/08/addressing Action"` // Attribute s:mustUnderstand not implemented
		MessageID string `xml:"http://www.w3.org/2005/08/addressing MessageID"`
		ReplyTo   struct {
			Address string `xml:"http://www.w3.org/2005/08/addressing Address"`
		} `xml:"http://www.w3.org/2005/08/addressing ReplyTo"`
		To URL `xml:"http://www.w3.org/2005/08/addressing To"` // Attribute s:mustUnderstand not implemented
		Security struct { // This is for OnPremise auth which is all this demo supports
			UsernameToken  struct {
				ID       string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd Id,attr"`
				Username string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Username,omitempty"`
				Password struct {
					Text string `xml:",chardata"`
					Type string `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Type,attr,omitempty"`
				} `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Password"`
			} `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd UsernameToken"`
		} `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd Security"` // Attribute s:mustUnderstand not implemented
	} `xml:"http://www.w3.org/2003/05/soap-envelope Header"`
	Body struct {
		GetPolicies struct {
			Client struct {
				// TODO: Use These Values correctly - Probs return again in response
				LastUpdate struct {
					Text string `xml:",chardata"`
					Nil  string `xml:"nil,attr"` // TODO: ?
				} `xml:"lastUpdate"`
				PreferredLanguage struct {
					Text string `xml:",chardata"`
					Nil  string `xml:"nil,attr"` // TODO: ?
				} `xml:"preferredLanguage"`
			} `xml:"client"`
			RequestFilter struct {
				Text string `xml:",chardata"`
				Nil  string `xml:"nil,attr"` // TODO: ?
			} `xml:"requestFilter"`
		} `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy GetPolicies"`
	} `xml:"http://www.w3.org/2003/05/soap-envelope Body"` // Attribute xmlns:xsd & xmlns:xsi not implemented
}

func (cmd *MdePolicyServiceRequest) Decode(b io.ReadCloser) error {
	return xml.NewDecoder(b).Decode(cmd)
}

func (cmd MdePolicyServiceRequest) Verify() error {
	if cmd.Header.Action != "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies" {
		return ErrInvalidAction
	}

	domain := strings.Split(cmd.Header.To.Host, ":")
	if len(domain) > 2 || len(domain) == 0 || domain[0] == "" {
		return ErrEmptyToDomain
	}

	if cmd.Header.To.Path != "/EnrollmentServer/PolicyService.svc" {
		return ErrInvalidToPath
	}

	if cmd.Header.MessageID == "" {
		return ErrEmptyMessageID
	}

	if cmd.Header.ReplyTo.Address == "" {
		return ErrEmptyReplyToAddress
	}

	// The below checks are just for On Premise Auth which is all this demo supports.

	if cmd.Header.Security.UsernameToken.Username == "" {
		return ErrEmptyUsername
	}

	if cmd.Header.Security.UsernameToken.ID != "uuid-cc1ccc1f-2fba-4bcf-b063-ffc0cac77917-4" {
		return ErrInvalidUsernameToken
	}

	if cmd.Header.Security.UsernameToken.Password.Text == "" {
		return ErrEmptyPassword
	}

	if cmd.Header.Security.UsernameToken.Password.Type != "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText" {
		return ErrInvalidPasswordType
	}

	return nil
}

type MdePolicyServiceResponse struct {
	// AuthPolicy                 string `xml:"DiscoverResult>AuthPolicy"`
	// EnrollmentPolicyServiceURL string `xml:"DiscoverResult>EnrollmentPolicyServiceUrl,omitempty"`
	// EnrollmentServiceURL       string `xml:"DiscoverResult>EnrollmentServiceUrl"`
	// AuthenticationServiceUrl   string `xml:"DiscoverResult>AuthenticationServiceUrl,omitempty"`
	// EnrollmentVersion          string `xml:"DiscoverResult>EnrollmentVersion,omitempty"`
}
