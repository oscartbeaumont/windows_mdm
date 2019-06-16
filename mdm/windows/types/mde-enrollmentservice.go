package windowstype

import (
	"errors"
	"strings"
	"encoding/xml"
	"io"
)

var ( // TODO: Clean Error Messages
	ErrInvalidBinarySecurityTokenType = errors.New("invalid binary security TokenType")
	ErrInvalidBinarySecurityEncodingType = errors.New("invalid binary security EncodingType")
	ErrInvalidBinarySecurityRequestType = errors.New("invalid binary security RequestType")
	ErrInvalidBinarySecurityValueType = errors.New("invalid binary security ValueType")
)

type MdeEnrollmentServiceRequest struct {
	// XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"` // Attribute xmlns:a, xmlns:s, xmlns:u, xmlns:wsse, xmlns:wst & xmlns:ac not implemented
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
		RequestSecurityToken struct {
			// TODO: Verify These Values in Verify()
			TokenType           string `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 TokenType"`
			RequestType         string `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestType"`
			BinarySecurityToken struct {
				Text         string `xml:",chardata"`
				ValueType    string `xml:"ValueType,attr"`
				EncodingType string `xml:"EncodingType,attr"`
			} `xml:"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd BinarySecurityToken"`
			AdditionalContext struct {
				ContextItems []struct {
					Name  string `xml:"Name,attr"`
					Value string `xml:"http://schemas.xmlsoap.org/ws/2006/12/authorization Value"`
				} `xml:"http://schemas.xmlsoap.org/ws/2006/12/authorization ContextItem"`
			} `xml:"http://schemas.xmlsoap.org/ws/2006/12/authorization AdditionalContext"`


		} `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityToken"`
	} `xml:"http://www.w3.org/2003/05/soap-envelope Body"` // Attribute xmlns:xsd & xmlns:xsi not implemented
}

func (cmd *MdeEnrollmentServiceRequest) Decode(b io.ReadCloser) error {
	return xml.NewDecoder(b).Decode(cmd)
}

func (cmd MdeEnrollmentServiceRequest) Verify() error {
	if cmd.Header.Action != "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep" {
		return ErrInvalidAction
	}

	domain := strings.Split(cmd.Header.To.Host, ":")
	if len(domain) > 2 || len(domain) == 0 || domain[0] == "" {
		return ErrEmptyToDomain
	}

	if cmd.Header.To.Path != "/EnrollmentServer/EnrollmentService.svc" {
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

	// Not On Premise Auth checks anymore

	if cmd.Body.RequestSecurityToken.TokenType != "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken" {
		return ErrInvalidBinarySecurityTokenType
	}

	if cmd.Body.RequestSecurityToken.BinarySecurityToken.EncodingType != "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary" {
		return ErrInvalidBinarySecurityEncodingType
	}

	// Spec doesn't say if the ones below are correct

	if cmd.Body.RequestSecurityToken.RequestType != "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue" {
		return ErrInvalidBinarySecurityRequestType
	}

	if cmd.Body.RequestSecurityToken.BinarySecurityToken.ValueType != "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" {
		return ErrInvalidBinarySecurityValueType
	}

	return nil
}

type MdeEnrollmentServiceResponse struct {
	// RequestSecurityTokenResponseCollection `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityTokenResponseCollection"`
	// RequestSecurityTokenResponseCollection struct {
	// 	Text                         string `xml:",chardata"`
	// 	Xmlns                        string `xml:"xmlns,attr"`
	// 	RequestSecurityTokenResponse struct {
	// 		Text               string `xml:",chardata"`
	// 		TokenType          string `xml:"TokenType"`
	// 		DispositionMessage struct {
	// 			Text  string `xml:",chardata"`
	// 			Xmlns string `xml:"xmlns,attr"`
	// 		} `xml:"DispositionMessage"`
	// 		RequestedSecurityToken struct {
	// 			Text                string `xml:",chardata"`
	// 			BinarySecurityToken struct {
	// 				Text         string `xml:",chardata"`
	// 				ValueType    string `xml:"ValueType,attr"`
	// 				EncodingType string `xml:"EncodingType,attr"`
	// 				Xmlns        string `xml:"xmlns,attr"`
	// 			} `xml:"BinarySecurityToken"`
	// 		} `xml:"RequestedSecurityToken"`
	// 		RequestID struct {
	// 			Text  string `xml:",chardata"`
	// 			Xmlns string `xml:"xmlns,attr"`
	// 		} `xml:"RequestID"`
	// 	} `xml:"RequestSecurityTokenResponse"`
	// } `xml:"RequestSecurityTokenResponseCollection"`

	
	// AuthPolicy                 string `xml:"DiscoverResult>AuthPolicy"`
	// EnrollmentPolicyServiceURL string `xml:"DiscoverResult>EnrollmentPolicyServiceUrl,omitempty"`
	// EnrollmentServiceURL       string `xml:"DiscoverResult>EnrollmentServiceUrl"`
	// AuthenticationServiceUrl   string `xml:"DiscoverResult>AuthenticationServiceUrl,omitempty"`
	// EnrollmentVersion          string `xml:"DiscoverResult>EnrollmentVersion,omitempty"`
}

type WapProvisioningDoc struct {
	XMLName        xml.Name `xml:"wap-provisioningdoc"`
	Version        string   `xml:"version,attr"`
	Characteristic []WapCharacteristic `xml:"characteristic"`
}

func (cmd WapProvisioningDoc) Encode() ([]byte, error) {
	return xml.Marshal(cmd)
}

type WapCharacteristic struct {
	Type           string `xml:"type,attr,omitempty"`
	Characteristic []WapCharacteristic `xml:"characteristic,omitempty"`
	Param WapParm `xml:"parm,omitempty"`
}

type WapParm struct {
	// XMLName        xml.Name `xml:"parm,omitempty"`
	Name  string `xml:"name,attr,omitempty"`
	Value string `xml:"value,attr,omitempty"`
}