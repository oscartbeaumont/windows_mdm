package main

import (
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// TODO: This policy response throws a Warning and Error on the device but because its hidden from the user it is fine for now.

// PolicyHandler is the HTTP handler assosiated with the enrollment protocol's policy endpoint.
// It is at the URL: /EnrollmentServer/Policy.svc
func PolicyHandler(w http.ResponseWriter, r *http.Request) {
	// Read The HTTP Request body
	bodyRaw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	body := string(bodyRaw)

	// Retrieve the MessageID From The Body For The Response
	// Note: The XML isn't parsed to keep this example simple but in your server it would have to have been
	// So ignore the strings.Replace and Regex stuff you wouldn't do it this way
	messageID := strings.Replace(strings.Replace(regexp.MustCompile(`<a:MessageID>[\s\S]*?<\/a:MessageID>`).FindStringSubmatch(body)[0], "<a:MessageID>", "", -1), "</a:MessageID>", "", -1)

	// Create response payload
	response := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
	<s:Header>
	   <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>
	   <a:RelatesTo>` + messageID + `</a:RelatesTo>
	</s:Header>
	<s:Body xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	   <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
		 <xcep:response>
			 <policyID>d16de3a0-a087-4308-9344-e169fb528c0b</policyID>
			 <policyFriendlyName>Mattrax Identity</policyFriendlyName>
			 <nextUpdateHours>1</nextUpdateHours>
			 <policiesNotChanged>false</policiesNotChanged>
			 <policies>
				 <policy>
					 <policyOIDReference>0</policyOIDReference>
					 <cAs xsi:nil="true" />
					 <attributes>
						 <!--<commonName>CEPUnitTest</commonName>-->
						 <policySchema>3</policySchema>
						 <certificateValidity>
						 <validityPeriodSeconds>1209600</validityPeriodSeconds>
						 <renewalPeriodSeconds>172800</renewalPeriodSeconds>
						 </certificateValidity>
						 <permission>
						 <enroll>true</enroll>
						 <autoEnroll>false</autoEnroll>
						 </permission>
						 <privateKeyAttributes>
						 <minimalKeyLength>2048</minimalKeyLength>
						 <keySpec xsi:nil="true" />
						 <keyUsageProperty xsi:nil="true" />
						 <permissions xsi:nil="true" />
						 <algorithmOIDReference xsi:nil="true" />
						 <cryptoProviders xsi:nil="true" />
						 </privateKeyAttributes>
						 <revision>
						 <majorRevision>101</majorRevision>
						 <minorRevision>0</minorRevision>
						 </revision>
						 <supersededPolicies xsi:nil="true" />
						 <privateKeyFlags xsi:nil="true" />
						 <subjectNameFlags xsi:nil="true" />
						 <enrollmentFlags xsi:nil="true" />
						 <generalFlags xsi:nil="true" />
						 <hashAlgorithmOIDReference>0</hashAlgorithmOIDReference>
						 <rARequirements xsi:nil="true" />
						 <keyArchivalAttributes xsi:nil="true" />
						 <extensions xsi:nil="true" />
					 </attributes>
				 </policy>
			 </policies>
		 </response>
		 <xcep:cAs></xcep:cAs>
		 <xcep:oIDs></xcep:oIDs>
	   </GetPoliciesResponse>
	</s:Body>
 </s:Envelope>`)

	// Return request body
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Write(response)
}
