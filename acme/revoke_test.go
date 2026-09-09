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

package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// revokeTestServer serves a directory and a revokeCert endpoint, and records the
// decoded JOSE protected header of the revocation request so a test can tell
// which key signed it: an account key signs with "kid", a certificate key with
// "jwk". RFC 8555 §6.2.
func revokeTestServer(t *testing.T) (*Client, func() map[string]any) {
	t.Helper()

	var protected map[string]any
	mux := http.NewServeMux()

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   base + "/new-nonce",
			"newAccount": base + "/new-account",
			"newOrder":   base + "/new-order",
			"revokeCert": base + "/revoke-cert",
		})
	})
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "bm9uY2U")
	})
	mux.HandleFunc("/revoke-cert", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "bm9uY2Uy")
		body, _ := io.ReadAll(r.Body)
		var jws struct {
			Protected string `json:"protected"`
		}
		if err := json.Unmarshal(body, &jws); err == nil {
			if raw, err := base64.RawURLEncoding.DecodeString(jws.Protected); err == nil {
				_ = json.Unmarshal(raw, &protected)
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &Client{Directory: srv.URL + "/directory"}, func() map[string]any { return protected }
}

func revokeTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{SerialNumber: big.NewInt(1), Raw: []byte{0x30, 0x00}}
}

func revokeTestAccount(t *testing.T) Account {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Account{PrivateKey: key, Location: "https://ca.example/acct/1"}
}

// The doc comment on RevokeCertificate promises "If the certificate key is not
// provided, then the account key is used instead". Nothing in the body performs
// that substitution, so a nil certKey reaches jwsEncodeJSON, which calls
// key.Public() on it.
func TestRevokeCertificateWithoutCertKeyUsesAccountKey(t *testing.T) {
	client, protectedHeader := revokeTestServer(t)
	account := revokeTestAccount(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RevokeCertificate panicked on the documented nil certKey: %v", r)
		}
	}()

	if err := client.RevokeCertificate(context.Background(), account, revokeTestCert(t), nil, ReasonUnspecified); err != nil {
		t.Fatalf("revoking with the account key: %v", err)
	}

	h := protectedHeader()
	if h == nil {
		t.Fatal("no revocation request reached the server")
	}
	if _, ok := h["kid"]; !ok {
		t.Errorf("a request signed by the account key must carry kid, got header %v", h)
	}
	if _, ok := h["jwk"]; ok {
		t.Errorf("kid and jwk are mutually exclusive (§6.2), got header %v", h)
	}
}

// The guard against over-correcting: an explicitly supplied certificate key must
// still sign with jwk, which is the whole point of §7.6 allowing either key.
func TestRevokeCertificateWithCertKeySignsWithJWK(t *testing.T) {
	client, protectedHeader := revokeTestServer(t)
	account := revokeTestAccount(t)
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.RevokeCertificate(context.Background(), account, revokeTestCert(t), certKey, ReasonUnspecified); err != nil {
		t.Fatalf("revoking with the certificate key: %v", err)
	}

	h := protectedHeader()
	if _, ok := h["jwk"]; !ok {
		t.Errorf("a request signed by a certificate key must embed jwk, got header %v", h)
	}
	if _, ok := h["kid"]; ok {
		t.Errorf("kid and jwk are mutually exclusive (§6.2), got header %v", h)
	}
}

// Passing the account key explicitly is the same request as passing nil, and has
// always worked; it is here so the two paths are pinned to the same outcome.
func TestRevokeCertificateWithAccountKeyPassedExplicitly(t *testing.T) {
	client, protectedHeader := revokeTestServer(t)
	account := revokeTestAccount(t)

	if err := client.RevokeCertificate(context.Background(), account, revokeTestCert(t), account.PrivateKey, ReasonUnspecified); err != nil {
		t.Fatalf("revoking with the account key: %v", err)
	}

	h := protectedHeader()
	if _, ok := h["kid"]; !ok {
		t.Errorf("expected kid, got header %v", h)
	}
}

// With no key anywhere there is nothing to sign with. That must be an error the
// caller can handle, not a nil dereference inside the JWS encoder.
func TestRevokeCertificateWithNoKeyAtAllErrors(t *testing.T) {
	client, _ := revokeTestServer(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("RevokeCertificate panicked with no key available: %v", r)
		}
	}()

	err := client.RevokeCertificate(context.Background(), Account{}, revokeTestCert(t), nil, ReasonUnspecified)
	if err == nil {
		t.Fatal("expected an error when neither a certificate key nor an account key is available")
	}
	fmt.Fprintf(io.Discard, "%v", err)
}
