package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/acme"
	"log"
	"os"
	"time"
)

func main() {
	host := os.Getenv("HOST")
	email := os.Getenv("EMAIL")
	if host == "" || email == "" {
		log.Fatal("Missing HOST or EMAIL environment variables")
	}
	createCertificateViaLetsEncryptDns01Challenge(host, email)
}

func createCertificateViaLetsEncryptDns01Challenge(host, email string) {
	client, certificateKey := generateKeysAndClient(email)
	ctx, order := createOrder(host, client)
	baseChallenge, wildcardChallenge, baseAuthzURL, wildcardAuthzURL := fetchChallenges(ctx, client, order)
	baseKeyAuth, wildcardKeyAuth := generateChallengeRecords(client, baseChallenge, wildcardChallenge)
	promptUserForDnsSetup(host, baseKeyAuth, wildcardKeyAuth)
	acceptChallenges(ctx, client, baseChallenge, wildcardChallenge)
	waitForValidation(ctx, client, baseAuthzURL, wildcardAuthzURL)
	csr := generateAndValidateCSR(host, certificateKey)
	finalizeAndSaveCertificate(ctx, client, order, csr, certificateKey)
}

func generateKeysAndClient(email string) (*acme.Client, *rsa.PrivateKey) {
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate account private key: %v", err)
	}
	client := &acme.Client{Key: accountKey}
	certificateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate certificate private key: %v", err)
	}
	ctx := context.Background()
	account := &acme.Account{Contact: []string{"mailto:" + email}}
	_, err = client.Register(ctx, account, func(tosURL string) bool { return true })
	if err != nil {
		log.Fatalf("Failed to register ACME account: %v", err)
	}
	return client, certificateKey
}

func createOrder(host string, client *acme.Client) (context.Context, *acme.Order) {
	ctx := context.Background()
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{
		{Type: "dns", Value: host},
		{Type: "dns", Value: "*." + host},
	})
	if err != nil {
		log.Fatalf("Failed to authorize order: %v", err)
	}
	if len(order.AuthzURLs) < 2 {
		log.Fatalf("Expected at least 2 authorizations for base and wildcard domains")
	}
	return ctx, order
}

func fetchChallenges(ctx context.Context, client *acme.Client, order *acme.Order) (*acme.Challenge, *acme.Challenge, string, string) {
	baseAuthzURL := order.AuthzURLs[0]
	baseAz, err := client.GetAuthorization(ctx, baseAuthzURL)
	if err != nil {
		log.Fatalf("Failed to get base authorization: %v", err)
	}
	var baseChallenge *acme.Challenge
	for _, ch := range baseAz.Challenges {
		if ch.Type == "dns-01" {
			baseChallenge = ch
			break
		}
	}
	wildcardAuthzURL := order.AuthzURLs[1]
	wildcardAz, err := client.GetAuthorization(ctx, wildcardAuthzURL)
	if err != nil {
		log.Fatalf("Failed to get wildcard authorization: %v", err)
	}
	var wildcardChallenge *acme.Challenge
	for _, ch := range wildcardAz.Challenges {
		if ch.Type == "dns-01" {
			wildcardChallenge = ch
			break
		}
	}
	if baseChallenge == nil || wildcardChallenge == nil {
		log.Fatalf("DNS-01 challenges not found for base or wildcard domains")
	}
	return baseChallenge, wildcardChallenge, baseAuthzURL, wildcardAuthzURL
}

func generateChallengeRecords(client *acme.Client, baseChallenge, wildcardChallenge *acme.Challenge) (string, string) {
	baseKeyAuth, err := client.DNS01ChallengeRecord(baseChallenge.Token)
	if err != nil {
		log.Fatalf("Failed to generate DNS-01 challenge response for base domain: %v", err)
	}
	wildcardKeyAuth, err := client.DNS01ChallengeRecord(wildcardChallenge.Token)
	if err != nil {
		log.Fatalf("Failed to generate DNS-01 challenge response for wildcard domain: %v", err)
	}
	return baseKeyAuth, wildcardKeyAuth
}

func promptUserForDnsSetup(host, baseKeyAuth, wildcardKeyAuth string) {
	fmt.Printf("\nCreate a DNS TXT record for '_acme-challenge.%s' with:\n%s\n%s\n\nPress Enter to continue...\n", host, baseKeyAuth, wildcardKeyAuth)
	fmt.Scanln()
}

func acceptChallenges(ctx context.Context, client *acme.Client, baseChallenge, wildcardChallenge *acme.Challenge) {
	_, err := client.Accept(ctx, baseChallenge)
	if err != nil {
		log.Fatalf("Failed to accept base domain challenge: %v", err)
	}
	_, err = client.Accept(ctx, wildcardChallenge)
	if err != nil {
		log.Fatalf("Failed to accept wildcard domain challenge: %v", err)
	}
}

func waitForValidation(ctx context.Context, client *acme.Client, baseAuthzURL, wildcardAuthzURL string) {
	for {
		baseAz, err := client.GetAuthorization(ctx, baseAuthzURL)
		if err != nil {
			log.Fatalf("Failed to get base domain authorization: %v", err)
		}
		wildcardAz, err := client.GetAuthorization(ctx, wildcardAuthzURL)
		if err != nil {
			log.Fatalf("Failed to get wildcard domain authorization: %v", err)
		}
		if baseAz.Status == acme.StatusValid && wildcardAz.Status == acme.StatusValid {
			break
		}
		if baseAz.Status == acme.StatusInvalid || wildcardAz.Status == acme.StatusInvalid {
			log.Fatal("Challenge validation failed")
		}
		time.Sleep(2 * time.Second)
	}
}

func generateAndValidateCSR(host string, certificateKey *rsa.PrivateKey) []byte {
	csr := &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}, DNSNames: []string{host, "*." + host}}
	data, err := x509.CreateCertificateRequest(rand.Reader, csr, certificateKey)
	if err != nil {
		log.Fatalf("Failed to generate CSR: %v", err)
	}
	return data
}

func finalizeAndSaveCertificate(ctx context.Context, client *acme.Client, order *acme.Order, csr []byte, certificateKey *rsa.PrivateKey) {
	var cert [][]byte
	for {
		var err error
		cert, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
		if err != nil {
			fmt.Printf("Failed to finalize order: %v\nPress Enter to retry...\n", err)
			fmt.Scanln()
			continue
		}
		break
	}

	var certPem []byte
	for _, c := range cert {
		certPem = append(certPem, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c})...)
	}
	combinedPem := append(certPem, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certificateKey)})...)
	os.WriteFile("./fullchain.pem", combinedPem, 0600)
}
