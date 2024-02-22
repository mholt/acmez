// Copyright 2023 Mariano Cano
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
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

const usage = `Usage: STTY=-icanon attestation <csr-file>

<csr-file> A file with a certificate signing request or CSR.

To be able to run this example, we need to use a key that can be attested,
"step-ca" [1], for example, supports attestation using YubiKey 5 Series.

To configure "step-ca" with device-attest-01 support, you need to create an ACME
provisioner with the device-attest-01 challenge enabled. In the ca.json the
provisioner looks like this:

  {
    "type": "ACME",
    "name": "attestation",
    "challenges": [ "device-attest-01" ]
  }

After configuring "step-ca" the first thing that we need is to create a key in
one of the YubiKey slots. We're picking 82 in this example. To do this, we will
use "step" [2] with the "step-kms-plugin" [2], and we will run the following:

  step kms create "yubikey:slot-id=82?pin-value=123456"

Then we need to create a CSR signed by this new key. This CSR must include the
serial number in the Permanent Identifier Subject Alternative Name extension.
The serial number of a YubiKey is printed on the key, but it is also available
in an attestation certificate. You can see it running:

  step kms attest "yubikey:slot-id=82?pin-value=123456" | \
  step certificate inspect

To add the permanent identifier, we will need to use the following template:

  {
    "subject": {{ toJson .Subject }},
    "sans": [{
      "type": "permanentIdentifier",
      "value": {{ toJson .Subject}}
    }]
  }

Having the template in "attestation.tpl", and assuming the serial number is
123456789, we can get the proper CSR running:

  step certificate create --csr --template attestation.tpl \
  --kms "yubikey:?pin-value=123456" --key "yubikey:slot-id=82" \
  123456789 att.csr

With this we can run this program with the new CSR:

  STTY=-icanon attestation att.csr

The program will ask you to create an attestation of the ACME Key Authorization,
running:

  echo -n <key-authorization> | \
  step kms attest --format step "yubikey:slot-id=82?pin-value=123456"

Note that because the input that we need to paste is usually more than 1024
characters, the "STTY=-icanon" environment variable is required.

[1] step-ca         - https://github.com/smallstep/certificates
[2] step            - https://github.com/smallstep/cli
[3] step-kms-plugin - https://github.com/smallstep/step-kms-plugin`

func main() {
	if len(os.Args) != 2 {
		fmt.Println(usage)
		os.Exit(1)
	}

	if os.Getenv("STTY") != "-icanon" {
		fmt.Fprintln(os.Stderr, "Please run this program with the environment variable STTY=-icanon")
		os.Exit(2)
	}

	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		log.Fatal("error reading CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	if err := attestationExample(csr); err != nil {
		log.Fatal(err)
	}
}

func attestationExample(csr *x509.CertificateRequest) error {
	// A context allows us to cancel long-running ops
	ctx := context.Background()

	// Logging is important - replace with your own zap logger
	logger, err := zap.NewDevelopment()
	if err != nil {
		return err
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

	// A high-level client embeds a low-level client and makes the ACME flow
	// much easier, but with less flexibility than using the low-level API
	// directly (see other example).
	//
	// This example implements it's own solver that requires you to provide the
	// device attestation statement.
	client := acmez.Client{
		Client: &acme.Client{
			Directory: "https://localhost:9000/acme/attestation/directory",
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
			acme.ChallengeTypeDeviceAttest01: attSolver{account},
		},
	}

	// If the account is new, we need to create it; only do this once!
	// then be sure to securely store the account key and metadata so
	// you can reuse it later!
	account, err = client.NewAccount(ctx, account)
	if err != nil {
		return fmt.Errorf("new account: %v", err)
	}

	// Do the ACME dance with the created account and get the certificates.
	certs, err := client.ObtainCertificateUsingCSR(ctx, account, csr)
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

// attSolver is a acmez.Solver That requires you to provide the attestation
// statement.
type attSolver struct {
	account acme.Account
}

func (s attSolver) Present(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] present: %#v", chal)
	return nil
}

func (s attSolver) CleanUp(ctx context.Context, chal acme.Challenge) error {
	log.Printf("[DEBUG] cleanup: %#v", chal)
	return nil
}

func (s attSolver) Payload(ctx context.Context, chal acme.Challenge) (any, error) {
	log.Printf("[DEBUG] payload: %#v", chal)

	// Calculate key authorization. This is the data that we need to sign to
	// validate the device attestation challenge.
	thumbprint, err := jwkThumbprint(s.account.PrivateKey.Public())
	if err != nil {
		return nil, err
	}
	keyAuthorization := fmt.Sprintf("%s.%s", chal.Token, thumbprint)

	fmt.Println()
	fmt.Println("Now you need to sign following keyAuthorization:")
	fmt.Println(keyAuthorization)
	fmt.Println()
	fmt.Println("To do this you can use step-kms-plugin running:")
	fmt.Printf("echo -n %s | step kms attest --format step \"yubikey:slot-id=82?pin-value=123456\"\n", keyAuthorization)
	fmt.Println()
	fmt.Println("Please enter the base64 output and press Enter:")
	reader := bufio.NewReaderSize(os.Stdin, 4096)
	attObj, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"attObj": attObj,
	}, nil
}

// jwkThumbprint creates a JWK thumbprint out of pub
// as specified in https://tools.ietf.org/html/rfc7638.
func jwkThumbprint(pub crypto.PublicKey) (string, error) {
	jwk, err := jwkEncode(pub)
	if err != nil {
		return "", err
	}
	b := sha256.Sum256([]byte(jwk))
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// jwkEncode encodes public part of an RSA or ECDSA key into a JWK.
// The result is also suitable for creating a JWK thumbprint.
// https://tools.ietf.org/html/rfc7517
func jwkEncode(pub crypto.PublicKey) (string, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.3.1
		n := pub.N
		e := big.NewInt(int64(pub.E))
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			base64.RawURLEncoding.EncodeToString(e.Bytes()),
			base64.RawURLEncoding.EncodeToString(n.Bytes()),
		), nil
	case *ecdsa.PublicKey:
		// https://tools.ietf.org/html/rfc7518#section-6.2.1
		p := pub.Curve.Params()
		n := p.BitSize / 8
		if p.BitSize%8 != 0 {
			n++
		}
		x := pub.X.Bytes()
		if n > len(x) {
			x = append(make([]byte, n-len(x)), x...)
		}
		y := pub.Y.Bytes()
		if n > len(y) {
			y = append(make([]byte, n-len(y)), y...)
		}
		// Field order is important.
		// See https://tools.ietf.org/html/rfc7638#section-3.3 for details.
		return fmt.Sprintf(`{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`,
			p.Name,
			base64.RawURLEncoding.EncodeToString(x),
			base64.RawURLEncoding.EncodeToString(y),
		), nil
	default:
		return "", fmt.Errorf("unsupported key type %T", pub)
	}
}
