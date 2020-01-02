package main

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EnrollHandler is the HTTP handler assosiated with the enrollment protocol's enrollment endpoint.
// It is at the URL: /EnrollmentServer/Policy.svc
func EnrollHandler(w http.ResponseWriter, r *http.Request) {
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

	// Retrieve the BinarySecurityToken (which contains a Certificate Signing Request) From The Body For The Response
	// Note: The XML isn't parsed to keep this example simple but in your server it would have to have been
	binarySecurityToken := strings.Replace(strings.Replace(regexp.MustCompile(`<wsse:BinarySecurityToken ValueType="http:\/\/schemas.microsoft.com\/windows\/pki\/2009\/01\/enrollment#PKCS10" EncodingType="http:\/\/docs\.oasis-open\.org\/wss\/2004\/01\/oasis-200401-wss-wssecurity-secext-1\.0\.xsd#base64binary">[\s\S]*?<\/wsse:BinarySecurityToken>`).FindStringSubmatch(body)[0], `<wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">`, "", -1), "</wsse:BinarySecurityToken>", "", -1)

	/* Sign binary security token */
	// Load raw Root CA
	rootCertificateDer, err := ioutil.ReadFile("./identity/identity.crt")
	if err != nil {
		panic(err)
	}
	rootPrivateKeyDer, err := ioutil.ReadFile("./identity/identity.key")
	if err != nil {
		panic(err)
	}

	// Convert the raw Root CA cert & key to parsed version
	rootCert, err := x509.ParseCertificate(rootCertificateDer)
	if err != nil {
		panic(err)
	}

	rootPrivateKey, err := x509.ParsePKCS1PrivateKey(rootPrivateKeyDer)
	if err != nil {
		panic(err)
	}

	// Decode Base64
	csrRaw, err := base64.StdEncoding.DecodeString(binarySecurityToken)
	if err != nil {
		panic(err)
	}

	// Decode and verify CSR
	csr, err := x509.ParseCertificateRequest(csrRaw)
	if err != nil {
		panic(err)
	}
	if err = csr.CheckSignature(); err != nil {
		panic(err)
	}

	// Create client identity certificate
	NotBefore1 := time.Now().Add(time.Duration(mathrand.Int31n(120)) * -time.Minute) // This randomises the creation time a bit for added security (Recommended by x509 signing article not the MDM spec)
	clientCertificate := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SerialNumber:       big.NewInt(2),
		Issuer:             rootCert.Issuer,
		Subject:            csr.Subject,
		NotBefore:          NotBefore1,
		NotAfter:           NotBefore1.Add(365 * 24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// Sign certificate with the identity
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, clientCertificate, rootCert, csr.PublicKey, rootPrivateKey)
	if err != nil {
		panic(err)
	}

	// Fingureprint (SHA-1 hash) of client certificate
	h := sha1.New()
	h.Write(clientCRTRaw)
	signedClientCertFingerprint := strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil))) // TODO: Cleanup -> This line is probally messer than it needs to be

	// Fingureprint (SHA-1 hash) of client certificate
	h2 := sha1.New()
	h2.Write(rootCertificateDer)
	identityCertFingerprint := strings.ToUpper(fmt.Sprintf("%x", h2.Sum(nil))) // TODO: Cleanup -> This line is probally messer than it needs to be

	/* End Sign binary security token */

	// Generate WAP provisioning profile for inside the payload
	wapProvisionProfile := []byte(`<wap-provisioningdoc version="1.1"><characteristic type="CertificateStore"><characteristic type="Root"><characteristic type="System"><characteristic type="` + identityCertFingerprint /* Root CA Certificate Fingureprint (SHA-1 hash of Der) */ + `"><parm name="EncodedCertificate" value="` + base64.StdEncoding.EncodeToString(rootCertificateDer) /* Base64 encoded root CA certificate */ + `"></parm></characteristic></characteristic></characteristic><characteristic type="My"><characteristic type="User"><characteristic type="` + signedClientCertFingerprint /* Signed Client Certificate (From the BinarySecurityToken) Fingureprint (SHA-1 hash of Der) */ + `"><parm name="EncodedCertificate" value="` + base64.StdEncoding.EncodeToString(clientCRTRaw) /* Base64 encoded signed certificate */ + `"></parm></characteristic><characteristic type="PrivateKeyContainer"><parm name="KeySpec" value="2"></parm><parm name="ContainerName" value="ConfigMgrEnrollment"></parm><parm name="ProviderType" value="1"></parm></characteristic></characteristic></characteristic></characteristic><characteristic type="APPLICATION"><parm name="APPID" value="w7"></parm><parm name="PROVIDER-ID" value="DEMO MDM"></parm><parm name="NAME" value="Windows MDM Demo Server"></parm><parm name="SSPHyperlink" value="http://go.microsoft.com/fwlink/?LinkId=255310"></parm><parm name="ADDR" value="https://` + domain + `/ManagementServer/MDM.svc"></parm><parm name="ServerList" value="https://` + domain + `/ManagementServer/ServerList.svc"></parm><parm name="ROLE" value="4294967295"></parm><parm name="CRLCheck" value="0"></parm><parm name="CONNRETRYFREQ" value="6"></parm><parm name="INITIALBACKOFFTIME" value="30000"></parm><parm name="MAXBACKOFFTIME" value="120000"></parm><parm name="BACKCOMPATRETRYDISABLED"></parm><parm name="DEFAULTENCODING" value="application/vnd.syncml.dm+xml"></parm> ` /* I think this encoding is less secure but I don't understand how to decode the other one */ + `<characteristic type="APPAUTH"><parm name="AAUTHLEVEL" value="CLIENT"></parm><parm name="AAUTHTYPE" value="DIGEST"></parm><parm name="AAUTHSECRET" value="dummy"></parm><parm name="AAUTHDATA" value="nonce"></parm></characteristic><characteristic type="APPAUTH"><parm name="AAUTHLEVEL" value="APPSRV"></parm><parm name="AAUTHTYPE" value="DIGEST"></parm><parm name="AAUTHNAME" value="dummy"></parm><parm name="AAUTHSECRET" value="dummy"></parm><parm name="AAUTHDATA" value="nonce"></parm></characteristic></characteristic><characteristic type="Registry"><characteristic type="HKLM\Security\MachineEnrollment"><parm name="RenewalPeriod" value="363" datatype="integer"></parm></characteristic><characteristic type="HKLM\Security\MachineEnrollment\OmaDmRetry"><parm name="NumRetries" value="8" datatype="integer"></parm><parm name="RetryInterval" value="15" datatype="integer"></parm><parm name="AuxNumRetries" value="5" datatype="integer"></parm><parm name="AuxRetryInterval" value="3" datatype="integer"></parm><parm name="Aux2NumRetries" value="0" datatype="integer"></parm><parm name="Aux2RetryInterval" value="480" datatype="integer"></parm></characteristic></characteristic><characteristic type="Registry"><characteristic type="HKLM\Software\Windows\CurrentVersion\MDM\MachineEnrollment"><parm name="DeviceName" value="TODO" datatype="string"></parm></characteristic></characteristic><characteristic type="Registry"><characteristic type="HKLM\SOFTWARE\Windows\CurrentVersion\MDM\MachineEnrollment"><parm name="SslServerRootCertHash" value="` + identityCertFingerprint /* Root CA Certificate Fingureprint (SHA-1 hash of Der) */ + `" datatype="string"></parm><parm name="SslClientCertStore" value="MY%5CSystem" datatype="string"></parm><parm name="SslClientCertSubjectName" value="Subject=CN=%3d` + "1B41A7C7-CE9C-4FFF-88B9-19983C!8EA85EFA0CAA9049AD575E61F44A4B12�" /* CommonName of the signed cetrificate. In this case the command named request in the CSR (BinarySecurityToken) */ + `" datatype="string"></parm><parm name="SslClientCertHash" value="` + signedClientCertFingerprint /* Signed Client Certificate (From the BinarySecurityToken) Fingureprint (SHA-1 hash of Der) */ + `" datatype="string"></parm></characteristic><characteristic type="HKLM\Security\Provisioning\OMADM\Accounts\037B1F0D3842015588E753CDE76EC724"><parm name="SslClientCertReference" value="My;System;` + signedClientCertFingerprint /* Signed Client Certificate (From the BinarySecurityToken) Fingureprint (SHA-1 hash of Der) */ + `" datatype="string"></parm></characteristic></characteristic></wap-provisioningdoc>`)

	// Create response payload
	response := []byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	    xmlns:a="http://www.w3.org/2005/08/addressing"
	    xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
	    <s:Header>
	        <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</a:Action>
	        <a:RelatesTo>` + messageID + `</a:RelatesTo>
	        <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
	            <u:Timestamp u:Id="_0">
	                <u:Created>2018-11-30T00:32:59.420Z</u:Created>
	                <u:Expires>2018-12-30T00:37:59.420Z</u:Expires>
	            </u:Timestamp>
	        </o:Security>
	    </s:Header>
	    <s:Body>
	        <RequestSecurityTokenResponseCollection xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
	            <RequestSecurityTokenResponse>
	                <TokenType>http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentToken</TokenType>
	                <DispositionMessage xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment"></DispositionMessage>
	                <RequestedSecurityToken>
	                    <BinarySecurityToken xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ValueType="http://schemas.microsoft.com/5.0.0.0/ConfigurationManager/Enrollment/DeviceEnrollmentProvisionDoc" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">` + base64.StdEncoding.EncodeToString(wapProvisionProfile) + `</BinarySecurityToken>
	                </RequestedSecurityToken>
	                <RequestID xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollment">0</RequestID>
	            </RequestSecurityTokenResponse>
	        </RequestSecurityTokenResponseCollection>
	    </s:Body>
	</s:Envelope>`)

	// Return request body
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	fmt.Println(string(response))
	w.Write(response)
}
