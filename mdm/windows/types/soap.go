package windowstype

import (
	"log" // TEMP
	"net/http"
	"encoding/xml"
	"strconv"

	"github.com/google/uuid"
)

type Envelope struct {
	XMLName xml.Name `xml:"s:Envelope"`
	S       string   `xml:"xmlns:s,attr,omitempty"`
	A       string   `xml:"xmlns:a,attr,omitempty"`
	Header Header `xml:"s:Header"`
	Body Body `xml:"s:Body"`
}

func (cmd *Envelope) Encode(w http.ResponseWriter) error { // TODO: Handle Non Using Chuncked Encoding
	response, err := xml.Marshal(cmd)
	if err != nil {
		return err
	}

	log.Println(string(response)) // TEMP

	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Transfer-Encoding", "identity")
	w.Write(response)

	return nil
}

type Header  struct {
	Action    MustUnderstand `xml:"a:Action"`
	ActivityID string `xml:"a:ActivityID"`
	RelatesTo string `xml:"a:RelatesTo"`
}

func NewHeader(action string, relatesto string) Header {
	uuid, err := uuid.NewRandom()
	if err != nil {
		panic(err) // TODO: Propper Error Handling
	}
	return Header{
		Action: MustUnderstand{
			MustUnderstand: "1",
			Value: action,
		},
		ActivityID: uuid.String(),
		RelatesTo: relatesto,
	}
}

type Body struct {
	Xsi              string           `xml:"xmlns:xsi,attr,omitempty"`
	Xsd              string           `xml:"xmlns:xsd,attr,omitempty"`

	MdeDiscoveryResponse MdeDiscoveryResponse `xml:"http://schemas.microsoft.com/windows/management/2012/01/enrollment DiscoverResponse,omitempty"`
	MdePolicyServiceResponse MdePolicyServiceResponse `xml:"http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy GetPoliciesResponse,omitempty"`
	MdeEnrollmentServiceResponse MdeEnrollmentServiceResponse `xml:"http://docs.oasis-open.org/ws-sx/ws-trust/200512 RequestSecurityTokenResponseCollection,omitempty"`
}

type MustUnderstand struct {
	MustUnderstand string `xml:"s:mustUnderstand,attr"`
	Value         string `xml:",innerxml"` // TODO: Maybe use interface{}
}

func NewMustUnderstand(i string) MustUnderstand {
	return MustUnderstand{
		MustUnderstand: "1",
		Value:         i,
	}
}