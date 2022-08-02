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
	"fmt"
	"log"
	"net/http"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

// Run pebble (the ACME server) before running this example:
//
// PEBBLE_VA_ALWAYS_VALID=1 pebble -config ./test/config/pebble-config.json -strict

func main() {
	err := highLevelExample()
	if err != nil {
		log.Fatal(err)
	}
}

func highLevelExample() error {
	// Put your domains here
	domains := []string{"example.com"}

	// A context allows us to cancel long-running ops
	ctx := context.Background()

	// Logging is important - replace with your own zap logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		return err
	}

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
	//
	// Implementing challenge solvers is outside the scope of this
	// example, but you can find a high-quality, general-purpose
	// solver for the dns-01 challenge in CertMagic:
	// https://pkg.go.dev/github.com/caddyserver/certmagic#DNS01Solver
	client := acmez.Client{
		Client: &acme.Client{
			Directory: "https://127.0.0.1:14000/dir", // default pebble endpoint
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
			acme.ChallengeTypeHTTP01:    mySolver{}, // provide these!
			acme.ChallengeTypeDNS01:     mySolver{}, // provide these!
			acme.ChallengeTypeTLSALPN01: mySolver{}, // provide these!
		},
	}

	// Before you can get a cert, you'll need an account registered with
	// the ACME CA; it needs a private key which should obviously be
	// different from any key used for certificates!
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

	// Every certificate needs a key.
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating certificate key: %v", err)
	}

	// Once your client, account, and certificate key are all ready,
	// it's time to request a certificate! The easiest way to do this
	// is to use ObtainCertificate() and pass in your list of domains
	// that you want on the cert. But if you need more flexibility, you
	// should create a CSR yourself and use ObtainCertificateUsingCSR().
	certs, err := client.ObtainCertificate(ctx, account, certPrivateKey, domains)
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

// mySolver is a no-op acmez.Solver for example purposes only.
type mySolver struct{}

func (s mySolver) Present(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] present: %#v", chal)
	return nil
}

func (s mySolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)
	return nil
}
