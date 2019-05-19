package torgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
)

//ServiceDesc contains services private key as well as hostname
type ServiceDesc struct {
	PrivateKey string
	Hostname   string
}

//ServiceDescV3 contains services private key as well as hostname
type ServiceDescV3 struct {
	PrivateKey []byte
	PublicKey  []byte
	Hostname   string
}

// Generate creats a V2 address
func Generate() (*ServiceDesc, error) {
	const PEM = "RSA PRIVATE KEY"
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}
	pub, err := asn1.Marshal(key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to encode public key: %v", err)
	}
	hashBytes := sha1.Sum(pub)
	hash := base32.StdEncoding.EncodeToString(hashBytes[:])
	exportedPriv := &pem.Block{
		Type:  PEM,
		Bytes: x509.MarshalPKCS1PrivateKey(key)}
	privateKey := pem.EncodeToMemory(exportedPriv)
	return &ServiceDesc{PrivateKey: string(privateKey), Hostname: strings.ToLower(hash[:16]) + ".onion"}, nil
}

// GenerateV3 creats a V3 address
func GenerateV3() (*ServiceDescV3, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %v", err)
	}

	checksumData := append([]byte(".onion checksum"), pub...)
	checksumData = append(checksumData, 3)

	hash := (sha512.Sum512(checksumData))

	checksum := hash[:2]

	addrData := append(pub, checksum...)
	addrData = append(addrData, 3)

	hostname := base32.StdEncoding.EncodeToString(addrData) + ".onion"
	return &ServiceDescV3{
		PrivateKey: append([]byte("== ed25519v1-secret: type0 ==\x00\x00\x00"), priv...),
		PublicKey:  append([]byte("== ed25519v1-public: type0 ==\x00\x00\x00"), pub...),
		Hostname:   hostname,
	}, nil
}
