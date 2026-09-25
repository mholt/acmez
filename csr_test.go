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

package acmez

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/mholt/acmez/v3/acme"
)

// csrWith builds and parses a real CSR so the extensions appear in the order
// x509.CreateCertificateRequest writes them: the SAN extension first, then
// anything from ExtraExtensions.
func csrWith(t *testing.T, dnsNames []string, extra []pkix.Extension) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames:        dnsNames,
		ExtraExtensions: extra,
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}
	return csr
}

func Test_createIdentifiersUsingCSR_tnAuthList(t *testing.T) {
	tnAuthListValue := []byte{0x30, 0x04, 0xa0, 0x02, 0x0c, 0x00}
	tnAuthList := pkix.Extension{Id: oidExtensionTNAuthList, Value: tnAuthListValue}
	tnAuthListID := acme.Identifier{
		Type:  "TNAuthList",
		Value: base64.RawURLEncoding.EncodeToString(tnAuthListValue),
	}
	dnsID := acme.Identifier{Type: "dns", Value: "example.com"}

	for _, tc := range []struct {
		name     string
		dnsNames []string
		want     []acme.Identifier
	}{
		{
			name: "TNAuthList alone",
			want: []acme.Identifier{tnAuthListID},
		},
		{
			// The SAN extension sorts before the TNAuthList one, so reading it
			// must not stop the walk over the remaining extensions.
			name:     "TNAuthList alongside a SAN",
			dnsNames: []string{"example.com"},
			want:     []acme.Identifier{dnsID, tnAuthListID},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := createIdentifiersUsingCSR(csrWith(t, tc.dnsNames, []pkix.Extension{tnAuthList}))
			if err != nil {
				t.Fatalf("createIdentifiersUsingCSR() error = %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("createIdentifiersUsingCSR() = %v, want %v", got, tc.want)
			}
		})
	}
}
