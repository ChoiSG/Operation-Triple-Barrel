package share

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

func GenerateKey() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}), nil
}

func GenerateKeyFile(path string) (string, error) {
	pemBytes, err := GenerateKey()
	if err != nil {
		return "", err
	}
	private, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return "", err
	}
	fp := FingerprintKey(private.PublicKey())

	if path == "-" {
		os.Stdout.Write(pemBytes)
		fmt.Fprintf(os.Stderr, "Fingerprint: %s\n", fp)
		return fp, nil
	}
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return "", err
	}
	return fp, nil
}

func FingerprintKey(k ssh.PublicKey) string {
	hash := sha256.Sum256(k.Marshal())
	return base64.StdEncoding.EncodeToString(hash[:])
}
