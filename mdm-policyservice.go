package main

import (
	"log"
	"net/http"
	"strconv"

	windowstype "github.com/oscartbeaumont/windows_mdm/mdm/windows/types"
)

// PolicyServiceHandler is a http.Handler which handles the Windows request to TODO
// TODO
func PolicyServiceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the method is GET tell the client the server exists with a 200 response. Else the request is a POST return the server configuration.
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Decode The HTTP Request Body From The Client To The cmd varible using the struct defined above.
		var cmd windowstype.MdePolicyServiceRequest
		if err := cmd.Decode(r.Body); err != nil {
			panic(err) // TODO: Error Handling
		}

		// // Use the verify function provided by the type to check it is correct
		if err := cmd.Verify(); err != nil {
			panic(err) // TODO: Error Handling
		}

		// Verify the server is the one the device thinks it is talking to. This is to prevent someone implementing a proxy with a different domain.
		// TODO: log.Println(cmd.Header.To.Host)

		// Verify the users email and password against login directory
		// TODO: log.Println(cmd.Header.Security.UsernameToken.Username + "  " + cmd.Header.Security.UsernameToken.Password.Text)
		// TODO: Can a gracefull error message be sent to the client cause if not just check the logijn in the enrollmentservice

		// Log Action
		log.Println("Username: " + cmd.Header.Security.UsernameToken.Username + " Password: " + cmd.Header.Security.UsernameToken.Password.Text + " Action: PolicyService")

		// Create Response
		// res := windowstype.Envelope{
		// 	S:      "http://www.w3.org/2003/05/soap-envelope",
		// 	A:      "http://www.w3.org/2005/08/addressing",
		// 	Header: windowstype.NewHeader("http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse", cmd.Header.MessageID),
		// 	Body: windowstype.Body{
		// 		MdePolicyServiceResponse: windowstype.MdePolicyServiceResponse{
		// 			// 				AuthPolicy:                 "OnPremise",
		// 			// 				EnrollmentVersion:          "4.0",
		// 			// 				EnrollmentPolicyServiceURL: "https://" + ConfigDomain + "/EnrollmentServer/PolicyService.svc", // TODO: Use propper url package for generation
		// 			// 				EnrollmentServiceURL:       "https://" + ConfigDomain + "/EnrollmentServer/EnrollmentService.svc", // TODO: Use propper url package for generation
		// 		},
		// 	},
		// }

		// // Send Response To The Client
		// if err := res.Encode(w); err != nil {
		// 	panic(err) // TODO: Error Handling
		// }

		// TODO:
		// 	- nextUpdateHours - What is a reccomneded value. I just made that one up for testing
		// 	- policiesNotChanged - Implement this functionality

		response := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
		   <s:Header>
			  <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse</a:Action>
			  <a:RelatesTo>` + cmd.Header.MessageID + `</a:RelatesTo>
		   </s:Header>
		   <s:Body xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
			  <GetPoliciesResponse xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
				<xcep:response>
					<policyID>` + "d16de3a0-a087-4308-9344-e169fb528c0b" + `</policyID>
					<policyFriendlyName>` + "Mattrax Identity" + `</policyFriendlyName>
					<nextUpdateHours>` + "1" + `</nextUpdateHours>
					<policiesNotChanged>` + "false" + `</policiesNotChanged>
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

		w.Header().Set("Content-Length", strconv.Itoa(len(response)))
		w.Header().Set("Transfer-Encoding", "identity")
		w.Write(response)
	}
}
