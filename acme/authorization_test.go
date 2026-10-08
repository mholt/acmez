package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPollAuthorizationRespectsPollTimeout(t *testing.T) {
	var server *httptest.Server

	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && r.URL.Path == "/new-nonce":
			w.Header().Set("Replay-Nonce", "test-nonce")
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && r.URL.Path == "/authz":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")

			authz := Authorization{
				Status:   StatusPending,
				Location: server.URL + "/authz",
			}
			_ = json.NewEncoder(w).Encode(authz)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	client := &Client{
		PollInterval: 10 * time.Millisecond,
		PollTimeout:  100 * time.Millisecond,
	}

	client.dir.NewNonce = server.URL + "/new-nonce"

	account := Account{
		PrivateKey: privateKey,
		Location:   "https://example.com/acme/acct/1",
	}

	authz := Authorization{
		Location: server.URL + "/authz",
		Status:   StatusPending,
	}
	start := time.Now()

	_, err = client.PollAuthorization(context.Background(), account, authz)

	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected PollAuthorization to time out")
	}

	if err.Error() != "authorization took too long" {
		t.Fatalf("unexpected error: %v", err)
	}

	if elapsed > 500*time.Millisecond {
		t.Fatalf("PollAuthorization exceeded timeout: elapsed %v", elapsed)
	}
}
