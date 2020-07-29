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

// Package acmez implements the higher-level flow of the ACME specification,
// RFC 8555: https://tools.ietf.org/html/rfc8555, specifically the sequence
// in Section 7.1 (page 21).
//
// It makes it easy to obtain certificates with various challenge types
// using pluggable challenge solvers, and provides some handy utilities for
// implementing solvers and using the certificates. It DOES NOT manage
// certificates, it only gets them from the ACME server.
//
// NOTE: This package's main function is to get a certificate, not manage it.
// Most users will want to *manage* certificates over the lifetime of a
// long-running program such as a HTTPS or TLS server, and should use CertMagic
// instead: https://github.com/caddyserver/certmagic.
package acmez

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	weakrand "math/rand"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mholt/acmez/acme"
	"go.uber.org/zap"
)

func init() {
	weakrand.Seed(time.Now().UnixNano())
}

// Client is a high-level API for ACME operations. It wraps
// a lower-level ACME client with useful functions to make
// common flows easier, especially for the issuance of
// certificates.
type Client struct {
	*acme.Client

	// Map of solvers keyed by name of the challenge type.
	ChallengeSolvers map[string]Solver

	// An optional logger. Default: no logs
	Logger *zap.Logger
}

// ObtainCertificateUsingCSR obtains all resulting certificate chains using the given CSR, which
// must be completely and properly filled out (particularly its DNSNames and Raw fields - this
// usually involves creating a template CSR, then calling x509.CreateCertificateRequest, then
// x509.ParseCertificateRequest on the output). The Subject CommonName is NOT considered.
//
// It implements every single part of the ACME flow described in RFC 8555 §7.1 with the exception
// of "Create account" because this method signature does not have a way to return the udpated
// account object. The account's status MUST be "valid" in order to succeed.
//
// As far as SANs go, this method currently only supports DNSNames on the csr.
func (c *Client) ObtainCertificateUsingCSR(ctx context.Context, account acme.Account, csr *x509.CertificateRequest) ([]acme.Certificate, error) {
	if account.Status != acme.StatusValid {
		return nil, fmt.Errorf("account status is not valid: %s", account.Status)
	}
	if csr == nil {
		return nil, fmt.Errorf("missing CSR")
	}

	var ids []acme.Identifier
	for _, name := range csr.DNSNames {
		ids = append(ids, acme.Identifier{
			Type:  "dns",
			Value: name,
		})
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no identifiers found")
	}

	order := acme.Order{Identifiers: ids}

	// create order for a new certificate
	order, err := c.Client.NewOrder(ctx, account, order)
	if err != nil {
		return nil, fmt.Errorf("creating new order: %w", err)
	}

	// solve challenges to fulfill the order; we choose mutually-available
	// challenge types at random to avoid relying too much on one challenge,
	// then retry with other challenge types if necessary
	err = c.solveChallenges(ctx, account, order)
	if err != nil {
		var problem acme.Problem
		if errors.As(err, &problem) {
			authz := problem.Resource.(acme.Authorization)
			return nil, fmt.Errorf("solving challenge: %s: %w", authz.Identifier.Value, err)
		}
		return nil, fmt.Errorf("solving challenge: %w", err)
	}

	// finalize the order, which notifies the CA to issue us a certificate
	order, err = c.Client.FinalizeOrder(ctx, account, order, csr.Raw)
	if err != nil {
		return nil, fmt.Errorf("finalizing order: %w", err)
	}

	// finally, download the certificate
	certChains, err := c.Client.GetCertificateChain(ctx, account, order.Certificate)
	if err != nil {
		return nil, fmt.Errorf("downloading certificate chain: %w", err)
	}

	return certChains, nil
}

// ObtainCertificate is the same as ObtainCertificateUsingCSR, except it is a slight wrapper
// that generates the CSR for you. Doing so requires the private key you will be using for
// the certificate (different from the account private key). It obtains a certificate for
// the given SANs (domain names) using the provided account.
func (c *Client) ObtainCertificate(ctx context.Context, account acme.Account, certPrivateKey crypto.Signer, sans []string) ([]acme.Certificate, error) {
	if len(sans) == 0 {
		return nil, fmt.Errorf("no DNS names provided: %v", sans)
	}
	if certPrivateKey == nil {
		return nil, fmt.Errorf("missing certificate private key")
	}

	csrTemplate := new(x509.CertificateRequest)
	for _, name := range sans {
		if ip := net.ParseIP(name); ip != nil {
			csrTemplate.IPAddresses = append(csrTemplate.IPAddresses, ip)
		} else if strings.Contains(name, "@") {
			csrTemplate.EmailAddresses = append(csrTemplate.EmailAddresses, name)
		} else if u, err := url.Parse(name); err == nil && strings.Contains(name, "/") {
			csrTemplate.URIs = append(csrTemplate.URIs, u)
		} else {
			csrTemplate.DNSNames = append(csrTemplate.DNSNames, name)
		}
	}

	// to properly fill out the CSR, we need to create it, then parse it
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, certPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("generating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parsing generated CSR: %v", err)
	}

	return c.ObtainCertificateUsingCSR(ctx, account, csr)
}

func (c *Client) solveChallenges(ctx context.Context, account acme.Account, order acme.Order) error {
	// when the function returns, make sure we clean up any and all resources
	var err error
	var authzStates []*authzState
	defer func() {
		// always clean up all remaining challenge solvers
		for _, authz := range authzStates {
			err := authz.currentSolver.CleanUp(ctx, authz.currentChallenge)
			if err != nil {
				if c.Logger != nil {
					c.Logger.Error("cleaning up solver",
						zap.String("identifier", authz.Identifier.Value),
						zap.String("challenge_type", authz.currentChallenge.Type),
						zap.Error(err))
				}
			}
		}

		if err == nil {
			return
		}

		// if this function returns with an error, make sure to deactivate
		// all authorization objects so they don't "leak"
		// https://github.com/go-acme/lego/issues/383
		// https://github.com/go-acme/lego/issues/353
		for _, authzURL := range order.Authorizations {
			authz, err := c.Client.DeactivateAuthorization(ctx, account, authzURL)
			if err != nil && (authz.Status == acme.StatusValid || authz.Status == acme.StatusPending) {
				if c.Logger != nil {
					c.Logger.Error("deactivating authorization",
						zap.String("identifier", authz.Identifier.Value),
						zap.String("authz", authzURL),
						zap.Error(err))
				}
			}
		}
	}()

	// start by allowing each authz's solver to present for its challenge
	for _, authzURL := range order.Authorizations {
		authz := &authzState{account: account}
		authz.Authorization, err = c.Client.GetAuthorization(ctx, account, authzURL)
		if err != nil {
			return err
		}
		if authz.Status == acme.StatusValid {
			continue
		}

		// we'll be shuffling and splicing the list of challenges, and we don't
		// don't want to affect the original list so make a copy
		authz.remainingChallenges = make([]acme.Challenge, len(authz.Challenges))
		copy(authz.remainingChallenges, authz.Challenges)

		// randomize the order of challenges so that we don't passively
		// rely on any one particular challenge type
		weakrand.Shuffle(len(authz.remainingChallenges), func(i, j int) {
			authz.remainingChallenges[i], authz.remainingChallenges[j] =
				authz.remainingChallenges[j], authz.remainingChallenges[i]
		})

		err = c.presentForNextChallenge(ctx, authz)
		if err != nil {
			return err
		}

		authzStates = append(authzStates, authz)
	}

	// sort authzs so that challenges which require waiting go first; no
	// point in getting authorizations quickly while others will take a
	// long time (that would eat into an authorization's validity period)
	sort.SliceStable(authzStates, func(i, j int) bool {
		_, iIsWaiter := authzStates[i].currentSolver.(Waiter)
		_, jIsWaiter := authzStates[j].currentSolver.(Waiter)
		// "if i is a waiter, and j is not a waiter, then i is less than j"
		return iIsWaiter && !jIsWaiter
	})

	// now that all solvers have had the opportunity to present, tell
	// the server to begin the challenges
	for _, authz := range authzStates {
		err = c.initiateCurrentChallenge(ctx, authz)
		if err != nil {
			return err
		}
	}

	// poll each authz to wait for completion of all challenges
	for len(authzStates) > 0 {
		// In §7.5.1, the spec says:
		//
		// "For challenges where the client can tell when the server has
		// validated the challenge (e.g., by seeing an HTTP or DNS request
		// from the server), the client SHOULD NOT begin polling until it has
		// seen the validation request from the server."
		//
		// However, in practice, this is difficult in the general case because
		// we would need to design some relatively-nuanced concurrency and hope
		// that the solver implementations also get their side right -- and the
		// fact that it's even possible only sometimes makes it harder, because
		// each solver needs a way to signal whether we should wait for its
		// approval. So no, I've decided not to implement that recommendation
		// in this particular library, but any implementations that use the lower
		// ACME API directly are welcome and encouraged to do so where possible.
		authz := authzStates[0]
		authz.Authorization, err = c.Client.PollAuthorization(ctx, account, authz.Authorization)

		// always clean up the challenge solver after polling, regardless of error
		cleanupErr := authz.currentSolver.CleanUp(ctx, authz.currentChallenge)
		if cleanupErr != nil {
			if c.Logger != nil {
				c.Logger.Error("cleaning up solver",
					zap.String("identifier", authz.Identifier.Value),
					zap.String("challenge_type", authz.currentChallenge.Type),
					zap.Error(err))
			}
		}

		if err != nil {
			var problem acme.Problem
			if errors.As(err, &problem) {
				switch problem.Type {
				case acme.ProblemTypeConnection,
					acme.ProblemTypeDNS,
					acme.ProblemTypeServerInternal,
					acme.ProblemTypeUnauthorized,
					acme.ProblemTypeTLS:
					// this error might be solved if we try another challenge type
					// (for example, client might be behind TLS termination which
					// would break the TLS-ALPN challenge, but the HTTP challenge
					// could still succeed)
					err = c.presentForNextChallenge(ctx, authz)
					if err != nil {
						return err
					}
					err = c.initiateCurrentChallenge(ctx, authz)
					if err != nil {
						return err
					}
					continue
				}
			}
			authzStates = authzStates[1:] // we already cleaned it up, so pop it
			return fmt.Errorf("[%s] %w", authz.Authorization.Identifier.Value, err)
		}

		authzStates = authzStates[1:]
	}

	return nil
}

func (c *Client) presentForNextChallenge(ctx context.Context, authz *authzState) error {
	err := c.nextChallenge(authz)
	if err != nil {
		return err
	}

	if c.Logger != nil {
		c.Logger.Info("trying to solve challenge",
			zap.String("identifier", authz.Identifier.Value),
			zap.String("challenge_type", authz.currentChallenge.Type))
	}

	err = authz.currentSolver.Present(ctx, authz.currentChallenge)
	if err != nil {
		return fmt.Errorf("presenting for challenge: %w", err)
	}

	return nil
}

func (c *Client) initiateCurrentChallenge(ctx context.Context, authz *authzState) error {
	// by now, all challenges should have had an opportunity to present, so
	// if this solver needs more time to finish presenting, wait on it now
	// (yes, this does block the initiation of the other challenges, but
	// that's probably OK, since we can't finalize the order until the slow
	// challenges are done too)
	if waiter, ok := authz.currentSolver.(Waiter); ok {
		err := waiter.Wait(ctx, authz.currentChallenge)
		if err != nil {
			return fmt.Errorf("waiting for solver %T to be ready: %w", authz.currentSolver, err)
		}
	}

	// tell the server to initiate the challenge
	var err error
	authz.currentChallenge, err = c.Client.InitiateChallenge(ctx, authz.account, authz.currentChallenge)
	if err != nil {
		return fmt.Errorf("initiating challenge with server: %w", err)
	}

	if c.Logger != nil {
		c.Logger.Debug("challenge accepted",
			zap.String("identifier", authz.Identifier.Value),
			zap.String("challenge_type", authz.currentChallenge.Type))
	}

	return nil
}

func (c *Client) nextChallenge(authz *authzState) error {
	for len(authz.remainingChallenges) > 0 {
		authz.currentChallenge = authz.remainingChallenges[0]
		authz.remainingChallenges = authz.remainingChallenges[1:]
		authz.currentSolver = c.ChallengeSolvers[authz.currentChallenge.Type]
		if authz.currentSolver != nil {
			break
		}
		// we don't have a solver for this challenge type
		if c.Logger != nil {
			c.Logger.Debug("server offered unsupported challenge type",
				zap.String("identifier", authz.Identifier.Value),
				zap.String("challenge_type", authz.currentChallenge.Type))
		}
	}
	if authz.currentSolver == nil {
		return fmt.Errorf("no solvers available for %s (configured=%v offered=%v)",
			authz.Identifier.Value, c.enabledChallengeTypes(), authz.offeredChallenges())
	}
	return nil
}

func (c *Client) enabledChallengeTypes() []string {
	enabledChallenges := make([]string, 0, len(c.ChallengeSolvers))
	for name, val := range c.ChallengeSolvers {
		if val != nil {
			enabledChallenges = append(enabledChallenges, name)
		}
	}
	return enabledChallenges
}

type authzState struct {
	acme.Authorization
	account             acme.Account
	currentChallenge    acme.Challenge
	currentSolver       Solver
	remainingChallenges []acme.Challenge
}

func (authz authzState) offeredChallenges() []string {
	offeredChallenges := make([]string, 0, len(authz.Challenges))
	for _, chal := range authz.Challenges {
		offeredChallenges = append(offeredChallenges, chal.Type)
	}
	return offeredChallenges
}
