package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

func getPemFromFile(path string) *pem.Block {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panic("Error Loading The Raw Key File: ", err)
	}
	pem, _ := pem.Decode(raw)
	if pem == nil {
		log.Panic("Error Parsing The PEM")
	}
	return pem
}

func SignCert(raw []byte) ([]byte, []byte, string) {
	// Load CA Key
	rawPrivKey := getPemFromFile("depot/ca-unencypted.key")
	key, err := x509.ParsePKCS1PrivateKey(rawPrivKey.Bytes)
	if err != nil {
		log.Panic("Error Parsing The Private Key: ", err)
	}
	/* TODO: Future Encypted Version
	der, err := x509.DecryptPEMBlock(pemBlock, []byte("ca private key password"))
	if err != nil {
		panic(err)
	}
	*/

	//Load The CA Cert
	rawCert := getPemFromFile("depot/ca.pem")
	ca, err := x509.ParseCertificate(rawCert.Bytes)
	if err != nil {
		log.Panic("Error Parsing The Certificate", err)
	}

	//////////////////////////////////
	/////// Each Handler Below ///////
	//////////////////////////////////

	// Decode The Certificate Request
	formatted := append(append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n"), raw...), []byte("\n-----END CERTIFICATE REQUEST-----\n")...)
	p, _ := pem.Decode(formatted)
	if p == nil {
		log.Panic("Error Parsing The Devices PEM")
	}
	req, err := x509.ParseCertificateRequest(p.Bytes)
	if err != nil {
		log.Panic("Error Parsing The Certificate Request: ", err)
	}
	if err = req.CheckSignature(); err != nil {
		log.Panic("Error Checking The Signature Of The Certificate Request: ", err)
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          req.Signature,
		SignatureAlgorithm: req.SignatureAlgorithm,

		PublicKeyAlgorithm: req.PublicKeyAlgorithm,
		PublicKey:          req.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       ca.Subject,
		Subject:      pkix.Name{CommonName: "e4c6b893-07a7-4b24-878e-9d8602c3d289"}, //req.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(54 * 7 * 24 * time.Hour), // 1 Year
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, ca, req.PublicKey, key)
	if err != nil {
		panic(err)
	}

	return clientCRTRaw, ca.Raw, req.Subject.CommonName // rawCert.Bytes
}
