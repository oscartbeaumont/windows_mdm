package wstep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	mathrand "math/rand"
	"time"
	"crypto"
	"crypto/sha1"
	"encoding/asn1"
	"errors"
)

// GenerateSubjectKeyID generates SubjectKeyId used in Certificate
// ID is 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var pubBytes []byte
	var err error
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubBytes, err = asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only RSA public key is supported")
	}

	hash := sha1.Sum(pubBytes)

	return hash[:], nil
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct { // TODO: Do I Have To Have This
	N *big.Int
	E int
}

func ParseCert(certRaw []byte, keyRaw []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	certPem, _ := pem.Decode(certRaw)
	keyPem, _ := pem.Decode(keyRaw)

	// TODO: Check For Nil On Decode Result and Error Handle

	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		return nil, nil, err
	}

	key, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

const (
	PemTypeCertificate               = "CERTIFICATE"
	PemTypeKey                       = "RSA PRIVATE KEY"
	PemTypeCertificateSigningRequest = "CERTIFICATE REQUEST"
)

func NewIdentityCert(subject pkix.Name) ([]byte, []byte, error) { // TODO: Wrap Errors
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	subjectKeyID, err := generateSubjectKeyID(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	NotBefore := time.Now().Add(time.Duration(mathrand.Int31n(120)) * -time.Minute) // This randomises the time on the certificates a bit
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subject,
		NotBefore:             NotBefore,
		NotAfter:              NotBefore.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           nil,
		UnknownExtKeyUsage:    nil,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey
		// (excluding the tag, length, and number of unused bits)
		SubjectKeyId:                subjectKeyID,
		DNSNames:                    nil,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         nil,
	}

	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPemBlock := &pem.Block{Type: PemTypeCertificate, Bytes: certDer}
	keyPemBlock := &pem.Block{Type: PemTypeKey, Bytes: x509.MarshalPKCS1PrivateKey(key)}

	// TODO: Redo This Using Two Decodes
	keyPem := pem.EncodeToMemory(keyPemBlock)
	if keyPem == nil {
		return nil, nil, pem.Encode(ioutil.Discard, keyPemBlock) // failed to encode the private key as a PEM
	}

	// TODO: Redo This Using Two Decodes
	certPem := pem.EncodeToMemory(certPemBlock)
	if certPem == nil {
		return nil, nil, pem.Encode(ioutil.Discard, certPemBlock)
	}

	return certPem, keyPem, nil
}
