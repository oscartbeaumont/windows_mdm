package main

import (
	"net/http"

	"github.com/antchfx/xquery/xml"
)

// Return a 200 status to show the device a MDM server exists
func discoveryGETHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(""))
}

// Return the locations of the MDM server
func discoveryPOSTHandler(w http.ResponseWriter, r *http.Request) { // TODO: Handle The Device Trying To Join - Valid Windows Version, Authentication, etc
	soapBody, err := xmlquery.Parse(r.Body)
	if err != nil {
		panic(err)
	}
	MessageID := xmlquery.FindOne(soapBody, "//s:Header/a:MessageID").InnerText()

	// Send The Response
	w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
       xmlns:a="http://www.w3.org/2005/08/addressing">
      <s:Header>
        <a:Action s:mustUnderstand="1">
          http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse
        </a:Action>
        <ActivityId>
          d9eb2fdd-e38a-46ee-bd93-aea9dc86a3b8
        </ActivityId>
        <a:RelatesTo>` + MessageID + `</a:RelatesTo>
      </s:Header>
      <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <DiscoverResponse
           xmlns="http://schemas.microsoft.com/windows/management/2012/01/enrollment">
          <DiscoverResult>
            <AuthPolicy>OnPremise</AuthPolicy>
            <EnrollmentVersion>4.0</EnrollmentVersion>
            <EnrollmentPolicyServiceUrl>
              https://mdm.otbeaumont.me/EnrollmentServer/PolicyService.svc
            </EnrollmentPolicyServiceUrl>
            <EnrollmentServiceUrl>
              https://mdm.otbeaumont.me/EnrollmentServer/EnrollmentService.svc
            </EnrollmentServiceUrl>
          </DiscoverResult>
        </DiscoverResponse>
      </s:Body>
    </s:Envelope>`))
}
