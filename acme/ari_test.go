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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ariTestServer serves just enough of an ACME directory to reach the
// renewalInfo endpoint, which answers with whatever window the test names.
// It counts ARI requests so a test can tell a retry loop from a single call.
func ariTestServer(t *testing.T, window func() (start, end time.Time)) (*Client, *int) {
	t.Helper()

	var ariRequests int
	mux := http.NewServeMux()

	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"newNonce":    base + "/new-nonce",
			"newAccount":  base + "/new-account",
			"newOrder":    base + "/new-order",
			"renewalInfo": base + "/renewal-info",
		})
	})

	mux.HandleFunc("/renewal-info/", func(w http.ResponseWriter, _ *http.Request) {
		ariRequests++
		start, end := window()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"suggestedWindow":{"start":%q,"end":%q}}`,
			start.Format(time.RFC3339), end.Format(time.RFC3339))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &Client{Directory: srv.URL + "/directory"}, &ariRequests
}

func ariTestCert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:   big.NewInt(0x1234567890),
		AuthorityKeyId: []byte{0xde, 0xad, 0xbe, 0xef},
		DNSNames:       []string{"example.com"},
	}
}

// A window the client itself rejects must not be handed back as a result.
//
// RFC 9773 §4.2: on "a malformed response (e.g. an end timestamp which is
// equal to or precedes the start timestamp)" the client "SHOULD make its own
// determination of when to renew the certificate". GetRenewalInfo already
// classifies these windows as invalid and retries, so returning the last one
// with a nil error puts the caller on exactly the window the retry loop spent
// three attempts refusing. See #40, where such a window (from a real Google
// Trust Services certificate) reached the selection math and panicked.
func TestGetRenewalInfoRejectsInvalidWindow(t *testing.T) {
	instant := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	for _, tc := range []struct {
		name       string
		start, end time.Time
	}{
		{"zero-length window", instant, instant},
		{"end precedes start", instant, instant.Add(-time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, requests := ariTestServer(t, func() (time.Time, time.Time) {
				return tc.start, tc.end
			})

			ari, err := client.GetRenewalInfo(context.Background(), ariTestCert())
			if err == nil {
				t.Fatalf("expected an error for a window the client rejected, got %+v (HasWindow=%t, UniqueIdentifier=%q)",
					ari.SuggestedWindow, ari.HasWindow(), ari.UniqueIdentifier)
			}
			if *requests != 3 {
				t.Errorf("expected 3 attempts before giving up, got %d", *requests)
			}
		})
	}
}

// The guard against over-correcting: a healthy window still resolves, and the
// fields a caller keys on are all filled in.
func TestGetRenewalInfoAcceptsValidWindow(t *testing.T) {
	start := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	end := start.Add(48 * time.Hour)

	client, requests := ariTestServer(t, func() (time.Time, time.Time) {
		return start, end
	})

	ari, err := client.GetRenewalInfo(context.Background(), ariTestCert())
	if err != nil {
		t.Fatalf("valid window: %v", err)
	}
	if *requests != 1 {
		t.Errorf("a valid window must be accepted on the first attempt, got %d requests", *requests)
	}
	if !ari.HasWindow() {
		t.Error("HasWindow() must be true for a window the client accepted")
	}
	if ari.UniqueIdentifier == "" {
		t.Error("UniqueIdentifier must be stamped on an accepted result")
	}
	if ari.SelectedTime.Before(start) || ari.SelectedTime.After(end) {
		t.Errorf("SelectedTime %s is outside the suggested window [%s, %s]", ari.SelectedTime, start, end)
	}
}

// A window that only becomes valid on a later attempt is what the retry loop
// exists for, so it must still be picked up.
func TestGetRenewalInfoRetriesUntilWindowIsValid(t *testing.T) {
	start := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	end := start.Add(48 * time.Hour)

	attempt := 0
	client, requests := ariTestServer(t, func() (time.Time, time.Time) {
		attempt++
		if attempt < 2 {
			return start, start // degenerate on the first attempt only
		}
		return start, end
	})

	ari, err := client.GetRenewalInfo(context.Background(), ariTestCert())
	if err != nil {
		t.Fatalf("window valid on the second attempt: %v", err)
	}
	if *requests != 2 {
		t.Errorf("expected 2 attempts, got %d", *requests)
	}
	if !ari.SuggestedWindow.End.Equal(end) {
		t.Errorf("expected the second attempt's window, got end=%s", ari.SuggestedWindow.End)
	}
}
