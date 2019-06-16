package main

import (
	"log"
	// "crypto/sha1"
	"encoding/base64"
	// "fmt"
	// "io/ioutil"

	"net/http"

	"strconv"
	// "strings"

	// TEMP

	windowstype "github.com/oscartbeaumont/windows_mdm/mdm/windows/types" // TODO: rename windows/types cause then doesn't need white rename
	"github.com/oscartbeaumont/windows_mdm/mdm/windows/wstep"
)

// EnrollmentServiceHandler is a http.Handler which handles the Windows TODO
// TODO
func EnrollmentServiceHandler(Domain string, wstep wstep.Service, ProfileName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the method is GET tell the client the server exists with a 200 response. Else the request is a POST return the server configuration.
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Decode The HTTP Request Body From The Client To The cmd varible using the struct defined above.
		var cmd windowstype.MdeEnrollmentServiceRequest
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

		// Check the device is allowed to enroll, the user has permissions, ect

		// Store the devices details into the database in a partly enrolled state as the device is now confirmed to be able to enroll
		// TODO: log.Println(cmd.Body.RequestSecurityToken.AdditionalContext.ContextItems)

		// Log Action
		log.Println("Username: " + cmd.Header.Security.UsernameToken.Username + " Password: " + cmd.Header.Security.UsernameToken.Password.Text + " Action: EnrollmentService")

		// Sign The CSR From The Client
		signedCSR, err := wstep.SignRequest(cmd.Body.RequestSecurityToken.BinarySecurityToken.Text)
		if err != nil {
			panic(err) // TODO: Error Handling
		}

		// Create Response

		// TODO: Extract This to struct
		// wapProvisioningDoc := windowstype.WapProvisioningDoc{
		// 	Version: "1.1",
		// 	Characteristic: []windowstype.WapCharacteristic{
		// 		windowstype.WapCharacteristic{
		// 			Type: "CertificateStore",
		// 			Characteristic: []windowstype.WapCharacteristic{
		// 				windowstype.WapCharacteristic{
		// 					Type: "Root",
		// 					Characteristic: []windowstype.WapCharacteristic{
		// 						windowstype.WapCharacteristic{
		// 							Type: "System",
		// 							Characteristic: []windowstype.WapCharacteristic{
		// 								windowstype.WapCharacteristic{
		// 									Type: wstep.CertFingureprint(),
		// 									Param: windowstype.WapParm{
		// 										Name: "EncodedCertificate",
		// 										Value: wstep.CertB64(),
		// 									},
		// 								},
		// 							},
		// 						},
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Type: "My",
		// 					Characteristic: []windowstype.WapCharacteristic{
		// 						windowstype.WapCharacteristic{
		// 							Type: "User",
		// 							Characteristic: []windowstype.WapCharacteristic{
		// 								windowstype.WapCharacteristic{
		// 									Param: windowstype.WapParm{
		// 										Name: "EncodedCertificate",
		// 										Value: signedCSR.CertB64(),
		// 									},
		// 								},
		// 								windowstype.WapCharacteristic{
		// 									Type: "PrivateKeyContainer",
		// 									Characteristic: []windowstype.WapCharacteristic{
		// 										windowstype.WapCharacteristic{
		// 											Param: windowstype.WapParm{
		// 												Name: "KeySpec",
		// 												Value: "2",
		// 											},
		// 										},
		// 										windowstype.WapCharacteristic{
		// 											Param: windowstype.WapParm{
		// 												Name: "ContainerName",
		// 												Value: "ConfigMgrEnrollment",
		// 											},
		// 										},
		// 										windowstype.WapCharacteristic{
		// 											Param: windowstype.WapParm{
		// 												Name: "ProviderType",
		// 												Value: "1",
		// 											},
		// 										},
		// 									},
		// 								},
		// 							},
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},
		// 		windowstype.WapCharacteristic{
		// 			Type: "APPLICATION",
		// 			Characteristic: []windowstype.WapCharacteristic{
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "APPID",
		// 						Value: "v7",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "PROVIDER-ID",
		// 						Value: "Oscars Windows MDM Demo",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "NAME",
		// 						Value: ProfileName,
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "SSPHyperlink",
		// 						Value: "http://go.microsoft.com/fwlink/?LinkId=255310", // Enterprise Management App
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "ADDR",
		// 						Value: "https://" + Domain + "/MDMHandlerADDR", // TODO: Propper URL Generation
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "ServerList",
		// 						Value: "https://" + Domain + "/MDMHandlerServerList", // TODO: Propper URL Generation
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "ROLE",
		// 						Value: "4294967295", // ? Possible Values
		// 					},
		// 				},
		// 				/* Discriminator to set whether the client should do Certificate Revocation List checking. */
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "CRLCheck",
		// 						Value: "0",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "CONNRETRYFREQ",
		// 						Value: "6",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "INITIALBACKOFFTIME",
		// 						Value: "30000",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "MAXBACKOFFTIME",
		// 						Value: "120000",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "BACKCOMPATRETRYDISABLED",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "DEFAULTENCODING",
		// 						Value: "application/vnd.syncml.dm+wbxml",
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Param: windowstype.WapParm{
		// 						Name: "SSLCLIENTCERTSEARCHCRITERIA",
		// 						Value: "Subject=CN%3de4c6b893-07a7-4b24-878e-9d8602c3d289&amp;Stores=MY%5CUser", // TODO: Correct Value
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Type: "APPAUTH",
		// 					Characteristic: []windowstype.WapCharacteristic{
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHLEVEL",
		// 								Value: "CLIENT",
		// 							},
		// 						},
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHTYPE",
		// 								Value: "DIGEST",
		// 							},
		// 						},
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHSECRET",
		// 								Value: "dummy",
		// 							},
		// 						},
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHDATA",
		// 								Value: "nonce",
		// 							},
		// 						},
		// 					},
		// 				},
		// 				windowstype.WapCharacteristic{
		// 					Type: "APPAUTH",
		// 					Characteristic: []windowstype.WapCharacteristic{
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHLEVEL",
		// 								Value: "APPSRV",
		// 							},
		// 						},
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHTYPE",
		// 								Value: "DIGEST",
		// 							},
		// 						},
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHNAME",
		// 								Value: "dummy",
		// 							},
		// 						},
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHSECRET",
		// 								Value: "dummy",
		// 							},
		// 						},
		// 						windowstype.WapCharacteristic{
		// 							Param: windowstype.WapParm{
		// 								Name: "AAUTHDATA",
		// 								Value: "nonce",
		// 							},
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},

		// 		windowstype.WapCharacteristic{
		// 			Type: "Registry",
		// 			Characteristic: []windowstype.WapCharacteristic{
		// 				// windowstype.WapCharacteristic{
		// 					Type: ""
		// 				// 	WapParm: windowstype.WapParm{
		// 				// 		Name: "AAUTHDATA",
		// 				// 		Value: "nonce",
		// 				// 	},
		// 				// },
		// 				// windowstype.WapCharacteristic{
		// 				// 	WapParm: windowstype.WapParm{
		// 				// 		Name: "AAUTHDATA",
		// 				// 		Value: "nonce",
		// 				// 	},
		// 				// },

		// 			},
		// 		},

		// 	},
		// }

		// internalPayload, err := wapProvisioningDoc.Encode() // TODO: Rename internalPayload
		// if err != nil {
		// 	panic(err) // TODO: Error Handling
		// }

		// log.Println(string(internalPayload))

		internalPayload := `<wap-provisioningdoc version="1.1">
			<characteristic type="CertificateStore">
			   <characteristic type="Root">
				  <characteristic type="System">
					 <characteristic type="` + wstep.CertFingureprint() + `">
						<parm name="EncodedCertificate" value="` + wstep.CertB64() + `" />
					 </characteristic>
				  </characteristic>
			   </characteristic>
			   <characteristic type="My">
				  <characteristic type="User">
					 <characteristic type="` + signedCSR.CertFingureprint() + `">
						<parm name="EncodedCertificate" value="` + signedCSR.CertB64() + `" />
						<characteristic type="PrivateKeyContainer">
						   <parm name="KeySpec" value="2" />
						   <parm name="ContainerName" value="ConfigMgrEnrollment" />
						   <parm name="ProviderType" value="1" />
						</characteristic>
					 </characteristic>
				  </characteristic>
			   </characteristic>
			</characteristic>


			<characteristic type="APPLICATION">
			   <parm name="APPID" value="w7" />
			   <parm name="PROVIDER-ID" value="` + "Oscars Windows MDM Demo" + `" />
			   <parm name="NAME" value="` + ProfileName + `" />
			   <parm name="SSPHyperlink" value="http://go.microsoft.com/fwlink/?LinkId=255310" />



			   <!-- Link to an application that the management service may provide eg a Windows Store application link. The Enrollment Client may show this link in its UX.-->
			   



			   <!-- Management Service URL. -->
			   <parm name="ADDR" value="https://` + Domain + `/MDMHandlerADDR" />
			   <parm name="ServerList" value="https://` + Domain + `/MDMHandlerServerList" />
			   <parm name="ROLE" value="4294967295" />
			   <!-- Discriminator to set whether the client should do Certificate Revocation List checking. -->
			   <parm name="CRLCheck" value="0" />
			   <parm name="CONNRETRYFREQ" value="6" />
			   <parm name="INITIALBACKOFFTIME" value="30000" />
			   <parm name="MAXBACKOFFTIME" value="120000" />
			   <parm name="BACKCOMPATRETRYDISABLED" />
			   <parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+wbxml" />
			   <!-- Search criteria for client to find the client certificate using subject name of the certificate -->
			   <parm name="SSLCLIENTCERTSEARCHCRITERIA" value="Subject=CN%3de4c6b893-07a7-4b24-878e-9d8602c3d289&amp;Stores=MY%5CUser" />
			   <characteristic type="APPAUTH">
				  <parm name="AAUTHLEVEL" value="CLIENT" />
				  <parm name="AAUTHTYPE" value="DIGEST" />
				  <parm name="AAUTHSECRET" value="dummy" />
				  <parm name="AAUTHDATA" value="nonce" />
			   </characteristic>
			   <characteristic type="APPAUTH">
				  <parm name="AAUTHLEVEL" value="APPSRV" />
				  <parm name="AAUTHTYPE" value="DIGEST" />
				  <parm name="AAUTHNAME" value="dummy" />
				  <parm name="AAUTHSECRET" value="dummy" />
				  <parm name="AAUTHDATA" value="nonce" />
			   </characteristic>
			</characteristic>
			<!-- Extra Information to seed the management agent’s behavior . -->
			<characteristic type="Registry">
			   <characteristic type="HKLM\Security\MachineEnrollment">
				  <parm name="RenewalPeriod" value="363" datatype="integer" />
			   </characteristic>
			   <characteristic type="HKLM\Security\MachineEnrollment\OmaDmRetry">
				  <!-- Number of retries if client fails to connect to the management service. -->
				  <parm name="NumRetries" value="8" datatype="integer" />
				  <!--Interval in minutes between retries. -->
				  <parm name="RetryInterval" value="15" datatype="integer" />
				  <parm name="AuxNumRetries" value="5" datatype="integer" />
				  <parm name="AuxRetryInterval" value="3" datatype="integer" />
				  <parm name="Aux2NumRetries" value="0" datatype="integer" />
				  <parm name="Aux2RetryInterval" value="480" datatype="integer" />
			   </characteristic>
			</characteristic>
			<!-- Extra Information about where to find device identity information.  This is redundant in that it is duplicative to what is above, but it is required in the current version of the protocol. -->
			<characteristic type="Registry">
			   <characteristic type="HKLM\Software\Windows\CurrentVersion\MDM\MachineEnrollment">
				  <parm name="DeviceName" value="" datatype="string" />
			   </characteristic>
			</characteristic>
			<characteristic type="Registry">
			   <characteristic type="HKLM\SOFTWARE\Windows\CurrentVersion\MDM\MachineEnrollment">
				  <!--Thumbprint of root certificate. -->
				  <parm name="SslServerRootCertHash" value="` + wstep.CertFingureprint() + `" datatype="string" />
				  <!-- Store for device certificate. -->
				  <parm name="SslClientCertStore" value="MY%5CSystem" datatype="string" />
				  <!--  Common name of issued certificate. -->
				  <parm name="SslClientCertSubjectName" value="CN%3de4c6b893-07a7-4b24-878e-9d8602c3d289" datatype="string" />
				  <!--Thumbprint of issued certificate. -->
				  <parm name="SslClientCertHash" value="` + signedCSR.CertFingureprint() + `" datatype="string" />
			   </characteristic>
			   <characteristic type="HKLM\Security\Provisioning\OMADM\Accounts\037B1F0D3842015588E753CDE76EC724">
				  <parm name="SslClientCertReference" value="My;System;B692158116B7B82EDA4600FF4145414933B0D5AB" datatype="string" />
			   </characteristic>
			</characteristic>
		 </wap-provisioningdoc>`

		// Send The Response
		response := []byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
		   xmlns:a="http://www.w3.org/2005/08/addressing"
		   xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
		   <s:Header>
		      <a:Action s:mustUnderstand="1" >
		         http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep
		      </a:Action>
		      <a:RelatesTo>` + cmd.Header.MessageID + `</a:RelatesTo>
		      <o:Security s:mustUnderstand="1" xmlns:o=
		         "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
		         <u:Timestamp u:Id="_0">
		            <u:Created>2018-11-30T00:32:59.420Z</u:Created>
		            <u:Expires>2018-12-30T00:37:59.420Z</u:Expires>
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
		                  ` + base64.StdEncoding.EncodeToString([]byte(internalPayload)) + `
		               </BinarySecurityToken>
		            </RequestedSecurityToken>
		            <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0
		            </RequestID>
		         </RequestSecurityTokenResponse>
		      </RequestSecurityTokenResponseCollection>
		   </s:Body>
		</s:Envelope>`)

		// Send The Response
		w.Header().Set("Content-Length", strconv.Itoa(len(response)))
		w.Header().Set("Transfer-Encoding", "identity")
		w.Write(response)
	}
}
