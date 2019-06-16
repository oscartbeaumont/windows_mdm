package wstep

import (
	"os"
	"log"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"time"
	"strings"
	"fmt"
	"io/ioutil"
	"crypto/rsa"
)

type Service struct {
	IdentityCert *x509.Certificate
	IdentityKey  *rsa.PrivateKey
}

func (srv *Service) Init(subject pkix.Name) error {
	certRaw, err := ioutil.ReadFile("identity.crt")
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	keyRaw, err := ioutil.ReadFile("identity.key")
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if certRaw == nil || keyRaw == nil {
		log.Println("Generating New Indentity CA")

		certRaw, keyRaw, err = NewIdentityCert(subject)
			if err != nil {
				return err
			}

		ioutil.WriteFile("identity.crt", certRaw, 0644) // TEMP
		ioutil.WriteFile("identity.key", keyRaw, 0644)
	}

	cert, key, err := ParseCert(certRaw, keyRaw)
	if err != nil {
		return err
	}
	srv.IdentityCert = cert
	srv.IdentityKey = key

	return nil
}

type SignedCSR []byte

func (csr SignedCSR) CertB64() string {
	return base64.StdEncoding.EncodeToString(csr)
}

func  (csr SignedCSR) CertFingureprint() string {
	h := sha1.New()
	h.Write(csr)
	return strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
}

func (srv Service) CertB64() string {
	return base64.StdEncoding.EncodeToString(srv.IdentityCert.Raw)
}

func  (srv Service) CertFingureprint() string {
	h := sha1.New()
	h.Write([]byte(srv.CertB64()))
	return strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
}

func (srv Service) SignRequest(binarySecurityToken string) (SignedCSR, error) {
	decoded, err := base64.StdEncoding.DecodeString(binarySecurityToken)
	if err != nil {
		return nil, err // TODO: Wrap Errors
	}

	csr, err := x509.ParseCertificateRequest(decoded)
	if err != nil {
		return nil, err // TODO: Wrap Errors
	}

	if err = csr.CheckSignature(); err != nil {
		return nil, err // TODO: Wrap Errors
	}

	clientCRTTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(2), // TODO: Should This be increasing?
		Issuer:       srv.IdentityCert.Subject,
		Subject:      csr.Subject, //pkix.Name{CommonName: "e4c6b893-07a7-4b24-878e-9d8602c3d289"}, // TODO: req.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(54 * 7 * 24 * time.Hour), // 1 Year // TODO: Confiurable + Store to DB so I know n per device basis when exipry and registered
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, srv.IdentityCert, csr.PublicKey, srv.IdentityKey)
	if err != nil {
		return nil, err // TODO: Wrap Error
	}

	return clientCRTRaw, nil
}