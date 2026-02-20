// Copyright 2026 oliverpool
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

package acmez_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"code.pfad.fr/check"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
)

func newHttpSolver(t *testing.T) (port int, solver acmez.Solver) {
	hsolver := &httpSolver{}
	s := httptest.NewServer(hsolver)
	t.Cleanup(s.Close)

	hostPort := s.Listener.Addr().String()
	_, sport, err := net.SplitHostPort(hostPort)
	check.Equal(t, nil, err)
	port, err = strconv.Atoi(sport)
	check.Equal(t, nil, err)

	return port, hsolver
}

type httpSolver struct {
	challenge atomic.Pointer[acme.Challenge]
}

// ServeHTTP implements http.Handler.
func (h *httpSolver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	chal := h.challenge.Load()
	if chal == nil || r.URL.Path != chal.HTTP01ResourcePath() || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	w.Header().Add("Content-Type", "text/plain")
	w.Write([]byte(chal.KeyAuthorization))
}

// Present implements Solver.
func (h *httpSolver) Present(ctx context.Context, chal acme.Challenge) error {
	h.challenge.Store(&chal)
	return nil
}

// CleanUp implements Solver.
func (h *httpSolver) CleanUp(context.Context, acme.Challenge) error {
	h.challenge.Store(nil)
	return nil
}

func TestAlreadyReplaced(t *testing.T) {
	solverPort, solver := newHttpSolver(t)
	client := newAcmeClient(t, solverPort, 0)
	c := acmez.Client{
		Client: client,
		ChallengeSolvers: map[string]acmez.Solver{
			"http-01": solver,
		},
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check.Equal(t, nil, err)
	account, err := c.NewAccount(t.Context(), acme.Account{
		TermsOfServiceAgreed: true,
		PrivateKey:           privateKey,
	})
	check.Equal(t, nil, err)

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check.Equal(t, nil, err)
	sans := []string{"127.0.0.1"}

	// initial cert
	initialCerts, err := c.ObtainCertificateForSANs(t.Context(), account, certKey, sans)
	check.Equal(t, nil, err)
	block, _ := pem.Decode(initialCerts[0].ChainPEM)
	toReplace, err := x509.ParseCertificate(block.Bytes)
	check.Equal(t, nil, err)

	{
		// initial relacement
		csr, err := acmez.NewCSR(certKey, sans)
		check.Equal(t, nil, err)
		params, err := acmez.OrderParametersFromCSR(account, csr)
		check.Equal(t, nil, err)
		params.Replaces = toReplace
		_, err = c.ObtainCertificate(t.Context(), params)
		check.Equal(t, nil, err)
	}

	{
		// second replacement (of the same certificate)
		csr, err := acmez.NewCSR(certKey, sans)
		check.Equal(t, nil, err)
		params, err := acmez.OrderParametersFromCSR(account, csr)
		check.Equal(t, nil, err)
		params.Replaces = toReplace
		_, err = c.ObtainCertificate(t.Context(), params)
		check.Equal(t, nil, err)
	}
}

func newAcmeClient(t *testing.T, httpPort, tlsPort int) *acme.Client {
	s := newPebbleServer(t, httpPort, tlsPort)
	return &acme.Client{
		Directory:  s.URL + wfe.DirectoryPath,
		HTTPClient: s.Client(),
		// Logger: slog.New(slog.NewTextHandler(t.Output(), nil)),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func newPebbleServer(t *testing.T, httpPort, tlsPort int) *httptest.Server {
	t.Setenv("PEBBLE_VA_NOSLEEP", "1") // https://github.com/letsencrypt/pebble/blob/23ab0beb482ac4760d7f3064141128a74d0d9430/va/va.go#L51
	// logger := log.New(t.Output(), "test", log.Llongfile)
	logger := log.New(io.Discard, "test", log.Llongfile)
	db := db.NewMemoryStore()
	keyAlg := "rsa"
	alternateRoots := 0
	chainLength := 1
	profiles := map[string]ca.Profile{
		"default": {
			Description:    "The default profile",
			ValidityPeriod: 0, // Will be overridden by the CA's default
		},
	}
	ca := ca.New(logger, db, "", keyAlg, alternateRoots, chainLength, profiles)
	va := va.New(logger, httpPort, tlsPort, true, "", db)
	wfeImpl := wfe.New(logger, db, va, ca, nil, true, false, 0, 0)

	s := httptest.NewUnstartedServer(wfeImpl.Handler())
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
