// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

// Run pebble (the ACME server) before running this example:
//
// PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/config/pebble-config.json -strict

func main() {
	err := getDelegateCert()
	if err != nil {
		log.Fatal(err)
	}
}
func getDelegateCert() error {
	// A context allows us to cancel long-running ops
	ctx := context.Background()

	// Logging is important - replace with your own logger
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// A high-level client embeds a low-level client and makes
	// the ACME flow much easier, but with less flexibility
	// than using the low-level API directly (see other example).
	//
	// One thing you will have to do is provide challenge solvers
	// for all the challenge types you wish to support. I recommend
	// supporting as many as possible in case there are errors. The
	// library will try all enabled challenge types, and certain
	// external factors can cause certain challenge types to fail,
	// where others might still succeed.

	client := acmez.Client{
		Client: &acme.Client{
			Directory: "https://127.0.0.1:8443/acme/somosacme/directory", // default pebble endpoint
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true, // REMOVE THIS FOR PRODUCTION USE!
					},
				},
			},
			Logger: logger,
		},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeAuthorityToken: AuthorityTokenChallengeSolver{}, // provide these!
		},
	}

	// Before you can get a cert, you'll need an account registered with
	// the ACME CA; it needs a private key which should obviously be
	// different from any key used for certificates! BE SURE TO SAVE THE
	// PRIVATE KEY SO YOU CAN REUSE THE ACCOUNT.
	accountPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating account key: %v", err)
	}
	account := acme.Account{
		Contact:              []string{"mailto:you@example.com"},
		TermsOfServiceAgreed: true,
		PrivateKey:           accountPrivateKey,
	}

	// If the account is new, we need to create it; only do this once!
	// then be sure to securely store the account key and metadata so
	// you can reuse it later!
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return fmt.Errorf("new account: %v", err)
	}

	csrPEM, err := DecodeBase64CSR("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQmNqQ0NBUmNDQVFBd1RqRUxNQWtHQTFVRUJoTUNWVk14R2pBWUJnTlZCQW9URVZOdmJXOXpJRVZ1WjJsdQpaV1Z5YVc1bk1TTXdJUVlEVlFRREV4b3dNVXBCT1RBek5qaElRbHBMVVRORVJ6SlRWa2hJUWpKRlVqQlpNQk1HCkJ5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCSEw0ekVLZnE0b0V0YzNXOUMwY3VDTmJqRDZWZFZ5RVFYZDAKZGt0cDZ5cm83SFZCS01TcmVyRDhJdVN4Yyt5ZjU5VnZtVmZyYmY1cG1NbTdqbG92UnlLZ1p6QmxCZ2txaGtpRwo5dzBCQ1E0eFdEQldNQjBHQ0NzR0FRVUZCd0VhQkJFd0Q2SU5GZ3N4T0RZMk9EQXdNVEV3TXpBTUJnTlZIUk1CCkFmOEVBakFBTUE0R0ExVWREd0VCL3dRRUF3SUhnREFYQmdOVkhTQUVFREFPTUF3R0NtQ0dTQUdHL3drQkFRUXcKQ2dZSUtvWkl6ajBFQXdJRFNRQXdSZ0loQU95WVd2VEZ5b0s4RVlYWDNtdThpREQxWFkzNGN0V1lxbWNXYUZWNQo3V3UwQWlFQTJCY1ozNlgxa0tJVEJOc3hxVlh0SGk5R2ErRWZYOWVwcmlnbzFJbys2eDg9Ci0tLS0tRU5EIENFUlRJRklDQVRFIFJFUVVFU1QtLS0tLQo=") // load your CSR here
	if err != nil {
		return fmt.Errorf("decoding CSR: %v", err)
	}

	// Once your client, account, and certificate key are all ready,
	// it's time to request a certificate! The easiest way to do this
	// is to use ObtainCertificateForSANs() and pass in your list of
	// domains that you want on the cert. But if you need more
	// flexibility, you should create a CSR yourself and use
	// ObtainCertificates().
	certs, err := client.ObtainCertificate(ctx, acmez.OrderParameters{
		Account: account,
		Identifiers: []acme.Identifier{
			{Type: "TNAuthList", Value: "MA+iDRYLMTg2NjgwMDExMDM="},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 1),
		CSR:       acmez.StaticCSR(csrPEM),
	})
	if err != nil {
		return fmt.Errorf("obtaining certificate: %v", err)
	}

	// ACME servers should usually give you the entire certificate chain
	// in PEM format, and sometimes even alternate chains! It's up to you
	// which one(s) to store and use, but whatever you do, be sure to
	// store the certificate and key somewhere safe and secure, i.e. don't
	// lose them!
	for _, cert := range certs {
		fmt.Printf("Certificate %q:\n%s\n\n", cert.URL, cert.ChainPEM)
	}

	return nil

}

func DecodeBase64CSR(base64CSR string) (*x509.CertificateRequest, error) {
	// Decode the base64 string
	pemData, err := base64.StdEncoding.DecodeString(base64CSR)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 CSR: %w", err)
	}

	// Parse the PEM block
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to parse PEM block or invalid type")
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return csr, nil
}

// mySolver is a no-op acmez.Solver for example purposes only.
type AuthorityTokenChallengeSolver struct{}

func (s AuthorityTokenChallengeSolver) Present(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] present: %#v", chal)
	return nil
}

func (s AuthorityTokenChallengeSolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)
	return nil
}

func (s AuthorityTokenChallengeSolver) Payload(ctx context.Context, chal acme.Challenge) (any, error) {
	log.Printf("[DEBUG] Payload: %#v", chal)
	return AuthorityTokenChallengeResponse{
		TkAuth: "eyJhbGciOiJFUzI1NiIsInR5cCI6IlJUVStKV1QiLCJ4NXUiOiJodHRwOi8vaG9zdC5kb2NrZXIuaW50ZXJuYWw6ODA4MC92MS9ydHVzL2tleXMvcHVia2V5LnBlbSJ9.eyJhdGMiOnsiY2EiOmZhbHNlLCJ0a3R5cGUiOiJUTkF1dGhMaXN0IiwidGt2YWx1ZSI6Ik1BK2lEUllMTVRnMk5qZ3dNREV4TURNPSJ9LCJleHAiOjE3NDA3ODMxOTQsImlhdCI6MTc0MDc3OTU5NCwiaXNzIjoiaHR0cDovL2hvc3QuZG9ja2VyLmludGVybmFsOjgwODAiLCJyb2lkIjoiQlJTTVMiLCJzdWIiOiJDSTZJa3BYVkNJc0luZzFkU0kiLCJ0biI6IjE4NjY4MDAxMTAzIn0.BUsKiGxXFHA8IHQ8J837QDzmgFFb0HY5YT6ZLKM4bkTsxyTCOZdyf5bn9jIm5x2rDxnBIuNyMOS6gw8Bp961hg",
	}, nil
}

type AuthorityTokenChallengeResponse struct {
	TkAuth string `json:"tkauth"`
}
