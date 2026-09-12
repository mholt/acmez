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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// Every response's Replay-Nonce used to be remembered, including the one from a
// newNonce request whose nonce Client.nonce() hands straight to its caller. The
// same nonce then went out twice, and the second use is rejected with badNonce.
func TestNonceIsHandedOutOnce(t *testing.T) {
	var newNonceRequests int
	mux := http.NewServeMux()
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, r *http.Request) {
		newNonceRequests++
		w.Header().Set(replayNonce, fmt.Sprintf("nonce%d", newNonceRequests))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// what provision() sets up for a real client
	client := &Client{Directory: srv.URL}
	client.dir.NewNonce = srv.URL + "/new-nonce"
	client.nonces = new(stack)

	var got []string
	for i := 0; i < 3; i++ {
		nonce, err := client.nonce(context.Background())
		if err != nil {
			t.Fatalf("nonce() error = %v", err)
		}
		got = append(got, nonce)
	}

	if want := []string{"nonce1", "nonce2", "nonce3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("nonces handed out = %v, want %v", got, want)
	}
	if newNonceRequests != 3 {
		t.Errorf("newNonce requests = %d, want 3", newNonceRequests)
	}
	if leftover := client.nonces.pop(); leftover != "" {
		t.Errorf("nonce %q was left in the pool as well as handed out", leftover)
	}
}

// A nonce the client is not consuming itself still has to be remembered. §6.5
func TestNonceFromOtherResponsesIsRemembered(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(replayNonce, "from-post")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &Client{Directory: srv.URL}
	client.dir.NewNonce = srv.URL + "/new-nonce"
	client.nonces = new(stack)

	if _, err := client.httpReq(context.Background(), http.MethodPost, srv.URL+"/order", []byte("{}"), nil); err != nil {
		t.Fatalf("httpReq() error = %v", err)
	}

	if nonce, err := client.nonce(context.Background()); err != nil || nonce != "from-post" {
		t.Errorf("nonce() = %q, %v; want %q from the pool", nonce, err, "from-post")
	}
}
