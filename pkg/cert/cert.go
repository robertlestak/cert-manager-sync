package cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func ParseCertificate(filename string) (*x509.Certificate, error) {
	certPem, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseCertificateFromBytes(certPem)
}

func ParseCertificateFromBytes(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
