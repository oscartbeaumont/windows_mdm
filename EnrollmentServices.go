package main

import (
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

func EnrollmentPolicyServiceHandler(w http.ResponseWriter, r *http.Request) {
	// Read The Body
	bodyRaw, _ := ioutil.ReadAll(r.Body)
	body := string(bodyRaw)

	// TODO: Verify The Users Login

	// Get The MessageID From The Body For The Response
	res := regexp.MustCompile(`<a:MessageID>[\s\S]*?<\/a:MessageID>`).FindStringSubmatch(body)
	MessageID := strings.Replace(strings.Replace(res[0], "<a:MessageID>", "", -1), "</a:MessageID>", "", -1)

	// Respond
	response := []byte(`<s:Envelope
         xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
         xmlns:s="http://www.w3.org/2003/05/soap-envelope"
         xmlns:a="http://www.w3.org/2005/08/addressing">
        <s:Header>
          <a:Action s:mustUnderstand="1">
            http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse
          </a:Action>
          <a:RelatesTo>` + MessageID + `</a:RelatesTo>
        </s:Header>
        <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema">
          <GetPoliciesResponse
             xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
            <response>
            <policyID />
              <policyFriendlyName xsi:nil="true"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
              <nextUpdateHours xsi:nil="true"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
              <policiesNotChanged xsi:nil="true"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>
              <policies>

              </policies>
            </response>
            <cAs xsi:nil="true" />
            <oIDs>

            </oIDs>
          </GetPoliciesResponse>
        </s:Body>
      </s:Envelope>`)

	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Transfer-Encoding", "identity")
	w.Write(response)
}

func EnrollmentServiceHandler(w http.ResponseWriter, r *http.Request) {
	// Read The Body
	bodyRaw, _ := ioutil.ReadAll(r.Body)
	body := string(bodyRaw)

	// TODO: Verify The Users Login

	// Get The MessageID From The Body For The Response
	res := regexp.MustCompile(`<a:MessageID>[\s\S]*?<\/a:MessageID>`).FindStringSubmatch(body)
	MessageID := strings.Replace(strings.Replace(res[0], "<a:MessageID>", "", -1), "</a:MessageID>", "", -1)

	// Get The Cert From The Body For The Response
	res2 := regexp.MustCompile(`<wsse:BinarySecurityToken [\s\S]*?<\/wsse:BinarySecurityToken>`).FindStringSubmatch(body)
	raw := strings.Replace(strings.Replace(res2[0], `<wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">`, "", -1), `</wsse:BinarySecurityToken>`, "", -1)

	CertRaw, CaCertRaw, CaSubject := SignCert([]byte(raw))
	Cert := base64.StdEncoding.EncodeToString(CertRaw)
	CaCert := base64.StdEncoding.EncodeToString(CaCertRaw)

	log.Println(CaSubject)

	// Respond
	wapProfile := base64.StdEncoding.EncodeToString([]byte(`<wap-provisioningdoc version="1.1">
    <characteristic type="CertificateStore">
        <characteristic type="Root">
            <characteristic type="System">
                <characteristic type="04E3576C4B59F0B4C24131A9287E0A38E8C791B3">
                    <parm name="EncodedCertificate"
                          value="` + CaCert + `"/>
                </characteristic>
            </characteristic>
        </characteristic>
        <characteristic type="My">
            <characteristic type="User">
                <characteristic type="PrivateKeyContainer"/>
                <characteristic type="62166E54AB0B0B9E7AB816FC8A287A8D771D090E">
                    <parm name="EncodedCertificate"
                          value="` + Cert + `"/>
                </characteristic>
            </characteristic>
            <characteristic type="WSTEP">
                <characteristic type="Renew">
                    <parm name="ROBOSupport" value="true" datatype="boolean"/>
                    <parm name="RenewPeriod" value="60" datatype="integer"/>
                    <parm name="RetryInterval" value="4" datatype="integer"/>
                </characteristic>
            </characteristic>
        </characteristic>
    </characteristic>
</wap-provisioningdoc>`))

	log.Println(wapProfile) //TEMP

	response := []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
       xmlns:a="http://www.w3.org/2005/08/addressing"
       xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
       <s:Header>
          <a:Action s:mustUnderstand="1" >
             http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep
          </a:Action>
          <a:RelatesTo>` + MessageID + `</a:RelatesTo>
          <o:Security s:mustUnderstand="1" xmlns:o=
             "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
             <u:Timestamp u:Id="_0">
               <u:Created>2018-09-26T02:46.420Z</u:Created> <!-- TODO: NOt Hardcoded Time -->
               <u:Expires>2018-09-27T00:00:01.420Z</u:Expires>
             </u:Timestamp>
          </o:Security>
       </s:Header>
       <s:Body>
          <RequestSecurityTokenResponseCollection
             xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
             <RequestSecurityTokenResponse>
                <TokenType>
        http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken
                </TokenType>
                 <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"/>           <RequestedSecurityToken>
                   <BinarySecurityToken
                      ValueType=
    "http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc"
                      EncodingType=
       "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"
                      xmlns=
              "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                      ` + wapProfile + `
                   </BinarySecurityToken>
                </RequestedSecurityToken>
                <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0
                </RequestID>
             </RequestSecurityTokenResponse>
          </RequestSecurityTokenResponseCollection>
       </s:Body>
    </s:Envelope>`)

	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Transfer-Encoding", "identity")
	w.Write(response)

	/*log.Println("")
	log.Println("")
	log.Println("")
	log.Println(string(response))
	log.Println("")*/
}
