package main

import (
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

func IndexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Windows MDM Server Demo In Go Lang!"))
}

func GetDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(""))
}

func PostDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	// Read The Body
	bodyRaw, _ := ioutil.ReadAll(r.Body)
	body := string(bodyRaw)

	// Get The MessageID From The Body For The Response
	res := regexp.MustCompile(`<a:MessageID>[\s\S]*?<\/a:MessageID>`).FindStringSubmatch(body)
	MessageID := strings.Replace(strings.Replace(res[0], "<a:MessageID>", "", -1), "</a:MessageID>", "", -1)

	// Respond
	response := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
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
            <EnrollmentVersion>3.0</EnrollmentVersion>
            <EnrollmentPolicyServiceUrl>
              https://mdm.otbeaumont.me/EnrollmentPolicyService.svc
            </EnrollmentPolicyServiceUrl>
            <EnrollmentServiceUrl>
              https://mdm.otbeaumont.me/EnrollmentService.svc
            </EnrollmentServiceUrl>
          </DiscoverResult>
        </DiscoverResponse>
      </s:Body>
    </s:Envelope>`)

	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Transfer-Encoding", "identity")
	w.Write(response)
}
