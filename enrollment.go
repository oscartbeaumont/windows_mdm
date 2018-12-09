package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/antchfx/xquery/xml"
)

// The Pem To Der Command: openssl x509 -outform der -in depot/ca.pem -out depot/ca.der
// To Decypt The Key File: openssl rsa -in depot/ca.key -out depot/ca-unencypted.key

//
func enrollmentPolicyHandler(w http.ResponseWriter, r *http.Request) { // TODO: Authentication, etc
	soapBody, err := xmlquery.Parse(r.Body)
	if err != nil {
		panic(err)
	}
	MessageID := xmlquery.FindOne(soapBody, "//s:Header/a:MessageID").InnerText()

	// Send The Response
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
            <cAs xsi:nil="true" />
            <oIDs>
              <oID>
                <value>1.3.14.3.2.29</value>
                <group>1</group>
                <oIDReferenceID>0</oIDReferenceID>
                <defaultName>szOID_OIWSEC_sha1RSASign</defaultName>
              </oID>
            </oIDs>
          </GetPoliciesResponse>
        </s:Body>
      </s:Envelope>`)

	// Send The Response
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Header().Set("Transfer-Encoding", "identity")
	w.Write(response)
}

//
func enrollmentWebServiceHandler(w http.ResponseWriter, r *http.Request) {
	soapBody, err := xmlquery.Parse(r.Body)
	if err != nil {
		panic(err)
	}
	MessageID := xmlquery.FindOne(soapBody, "//s:Header/a:MessageID").InnerText()
	binarySecurityToken := xmlquery.FindOne(soapBody, "//s:Body/wst:RequestSecurityToken/wsse:BinarySecurityToken").InnerText()
	log.Println(binarySecurityToken)

	// Sign The Clients Certificate Request
	clientCertRaw, CaCertRaw, CaSubject := SignCert([]byte(binarySecurityToken))
	//Cert := base64.StdEncoding.EncodeToString(CertRaw)
	//CaCert := base64.StdEncoding.EncodeToString(CaCertRaw)

	log.Println(CaSubject)

	// Construct The Response's Payload
	rootCertRaw, _ := ioutil.ReadFile("depot/ca.der")
	rootCert := base64.StdEncoding.EncodeToString([]byte(string(rootCertRaw)))
	h := sha1.New()
	h.Write(rootCertRaw)
	rootCertFigureprint := strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))

	log.Println("")
	log.Println("1)")
	log.Println(rootCert)
	log.Println("2)")
	log.Println(base64.StdEncoding.EncodeToString(CaCertRaw))
	log.Println("")

	//clientCertRaw := []byte("Failure") // TEMP
	clientCert := base64.StdEncoding.EncodeToString([]byte(string(clientCertRaw)))
	h2 := sha1.New()
	h2.Write(clientCertRaw)
	clientCertFingureprint := strings.ToUpper(fmt.Sprintf("%x", h2.Sum(nil)))

	internalPayload := `<wap-provisioningdoc version="1.1">
   <!-- This contains information about issued and trusted certificates. -->
   <characteristic type="CertificateStore">
     <!-- This contains trust certificates. -->
     <characteristic type="Root">
       <characteristic type="System">
         <!--The thumbprint of the certificate to be added to the trusted root store -->
         <characteristic type="` + rootCertFigureprint + `">
           <!-- Base64 encoding of the trust root certificate -->
           <parm name="EncodedCertificate" value="` + rootCert + `" />
         </characteristic>
       </characteristic>
     </characteristic>
       <!-- This contains intermediate certificates. -->
       <!--<characteristic type="CA">
         <characteristic type="System">
         <!—the thumbprint of the intermediate certificate 
         <characteristic type="5DF7DE78255449CFEBD82CD626011982378F40F1">
           <parm name="EncodedCertificate" value="MIIEwzCCA6ugAwIBAgIQAnwmjIOWnIlJSqpCJpUIrzANBgkqhkiG9w0BAQUFADBIMRMwEQYKCZImiZPyLGQBGRYDY29tMRkwFwYKCZImiZPyLGQBGRYJbWljcm9zb2Z0MRYwFAYDVQQDEw1TQ09ubGluZS1GQUtFMB4XDTEzMDkyNDE5NTcyOVoXDTE0MDkyNTE5NTcyOVowHzEdMBsGA1UEAwwUbWFuYWdlLm1pY3Jvc29mdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6EU35UODG4AncmJ4k8HAUzzRDNgcbntgznnBmurOzmRa2TrFZzabsMCT6TYjjejQsu0jDXfa8iKx7798T9RLo7/h79+DJHOCR7VRtA5PxYXu/s3ps9desic6RrKDibC0o/r7Mdo5CMcytSyk74DrNR6JzYGqY7Ge77OUx1zsev/9qRRx36nU6ZVgIIFnJtFm7y7rozPPWj9mKdXD3pBGqq3x6MiwBfvBwH3oCukRDAHBz/wmNoSQb+HjWwyuEhUNmn6KwrMmaArfCQTT2I8FyjMMpUaE+iVosk1uHI5L8dUHFS5aseNV3+yBwMTY2RVah/3/Sp8l913qmTfqDHLENAgMBAAGjggHQMIIBzDCCAYcGA1UdEQSCAX4wggF6gh1sb2dpbi5taWNyb3NvZnRvbmxpbmUtaW50LmNvbYIZbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbYIkRW50ZXJwcmlzZUVucm9sbG1lbnQuV0lOLThCQkc5RzBTUUIygiZFbnRlcnByaXNlRW5yb2xsbWVudC1zLldJTi04QkJHOUcwU1FCMoIdbG9naW4ubWljcm9zb2Z0b25saW5lLWludC5jb22CGWxvZ2luLm1pY3Jvc29mdG9ubGluZS5jb22CIkVudGVycHJpc2VFbnJvbGxtZW50Lm1pY3Jvc29mdC5jb22CJEVudGVycHJpc2VFbnJvbGxtZW50LXMubWljcm9zb2Z0LmNvbYIpRW50ZXJwcmlzZUVucm9sbG1lbnQubWFuYWdlLm1pY3Jvc29mdC5jb22CK0VudGVycHJpc2VFbnJvbGxtZW50LXMubWFuYWdlLm1pY3Jvc29mdC5jb22CFG1hbmFnZS5taWNyb3NvZnQuY29tMB0GA1UdDgQWBBTUvgeWP3R8TpdNrqZ++ixKnJspLjATBgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBLAwDQYJKoZIhvcNAQEFBQADggEBAJaVYeqsejoM3INNi11nvPnS+ttodnQweeCiv+U6EoTGIEsTztwqsdSRhc0PnfssfuegjqgdkKN/lAkysSqretYvEj/wIgKmrX0JqFFIkLjFRp3PrD5MFLLdlnxCZ65bVBLo607UlLe+tBlHhdebJEvwZF72RalYvPG33SU3pssSMczN3Mte6BbjtCpFUDSIwDEX+aUBs8kx35tiLNg8GpGtrVGem3MW3d5dOVvuYuWrgB86Yug09WHwsDGnck0cEyoJlsmoavkeYR5OYJnCylPDjZ5LX+ewlWFlWiUf8pD9Ph6fx292bE6/B5eVWxHXjxdvswYklJWNfbBis47mXRI=" />
           </characteristic>
         </characteristic>
       </characteristic>-->
     <characteristic type="My" >
       <characteristic type="User">
         <!-- Client certificate thumbprint. -->
         <characteristic type="` + clientCertFingureprint + `">
           <!-- Base64 encoding of the client certificate -->
           <parm name="EncodedCertificate" value="` + clientCert + `" />
           <characteristic type="PrivateKeyContainer">
             <parm name="KeySpec" value="2"/>
             <parm name="ContainerName" value="ConfigMgrEnrollment"/>
             <parm name="ProviderType" value="1"/>
           </characteristic>
         </characteristic>
       </characteristic>
     </characteristic>
   </characteristic>

   <!-- Contains information about the management service and configuration for the management agent -->
   <characteristic type="APPLICATION">
     <parm name="APPID" value="w7"/>
     <!-- Management Service Name. -->
     <parm name="PROVIDER-ID" value="Contoso Management Service"/>
     <parm name="NAME" value="BecMobile"/>
     <!-- Link to an application that the management service may provide eg a Windows Store application link. The Enrollment Client may show this link in its UX.-->
     <parm name="SSPHyperlink" value="http://go.microsoft.com/fwlink/?LinkId=255310" />
     <!-- Management Service URL. -->
     <parm name="ADDR" value="https://mdm.otbeaumont.me/MDMHandlerADDR"/>
     <parm name="ServerList" value="https://mdm.otbeaumont.me/MDMHandlerServerList" />
     <parm name="ROLE" value="4294967295"/>
     <!-- Discriminator to set whether the client should do Certificate Revocation List checking. -->
     <parm name="CRLCheck" value="0"/>
     <parm name="CONNRETRYFREQ" value="6" />
     <parm name="INITIALBACKOFFTIME" value="30000" />
     <parm name="MAXBACKOFFTIME" value="120000" />
     <parm name="BACKCOMPATRETRYDISABLED" />
     <parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+wbxml" />
     <!-- Search criteria for client to find the client certificate using subject name of the certificate -->
     <parm name="SSLCLIENTCERTSEARCHCRITERIA" value="Subject=CN%3de4c6b893-07a7-4b24-878e-9d8602c3d289&amp;Stores=MY%5CUser"/>
     <characteristic type="APPAUTH">
       <parm name="AAUTHLEVEL" value="CLIENT"/>
       <parm name="AAUTHTYPE" value="DIGEST"/>
       <parm name="AAUTHSECRET" value="dummy"/>
       <parm name="AAUTHDATA" value="nonce"/>
     </characteristic>
     <characteristic type="APPAUTH">
       <parm name="AAUTHLEVEL" value="APPSRV"/>
       <parm name="AAUTHTYPE" value="DIGEST"/>
       <parm name="AAUTHNAME" value="dummy"/>
       <parm name="AAUTHSECRET" value="dummy"/>
       <parm name="AAUTHDATA" value="nonce"/>
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
       <parm name="SslServerRootCertHash" value="` + rootCertFigureprint + `" datatype="string" />
       <!-- Store for device certificate. -->
       <parm name="SslClientCertStore" value="MY%5CSystem" datatype="string" />
       <!--  Common name of issued certificate. -->
       <parm name="SslClientCertSubjectName" value="CN%3de4c6b893-07a7-4b24-878e-9d8602c3d289" datatype="string" />
       <!--Thumbprint of issued certificate. -->
       <parm name="SslClientCertHash" value="` + clientCertFingureprint + `" datatype="string" />
     </characteristic>
     <characteristic type="HKLM\Security\Provisioning\OMADM\Accounts\037B1F0D3842015588E753CDE76EC724">
       <parm name="SslClientCertReference" value="My;System;B692158116B7B82EDA4600FF4145414933B0D5AB" datatype="string" />
     </characteristic>
   </characteristic>
 </wap-provisioningdoc>`

	log.Println("")
	log.Println(internalPayload)

	// Send The Response
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
