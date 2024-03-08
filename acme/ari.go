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
	"encoding/base64"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// TODO: (Feb. 2024) this quote will be outdated soon. See
// https://github.com/aarongable/draft-acme-ari/issues/55
//
// RenewalInfo "is a new resource type introduced to ACME protocol.
// This new resource both allows clients to query the server for
// suggestions on when they should renew certificates, and allows
// clients to inform the server when they have completed renewal
// (or otherwise replaced the certificate to their satisfaction)."
//
// ACME Renewal Information (ARI):
// https://www.ietf.org/archive/id/draft-ietf-acme-ari-03.html
//
// This is a DRAFT specification and the API is subject to change.
type RenewalInfo struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL"`

	// This field is not part of the specified structure, but
	// is important for proper conformance to the specification,
	// so this field will be populated with the Retry-After
	// response header value so the caller knows when to poll
	// again. Calling GetRenewalInfo again should not occur
	// before this time.
	RetryAfter time.Time `json:"-"`
}

// GetRenewalInfo returns the ACME Renewal Information (ARI) for the certificate.
// It fills in the Retry-After value, if present, onto the returned struct so
// the caller can poll appropriately.
func (c *Client) GetRenewalInfo(ctx context.Context, leafCert *x509.Certificate) (RenewalInfo, error) {
	if err := c.provision(ctx); err != nil {
		return RenewalInfo{}, err
	}

	var ari RenewalInfo
	resp, err := c.httpReq(ctx, http.MethodGet, c.ariEndpoint(leafCert), nil, &ari)
	if err != nil {
		return RenewalInfo{}, err
	}

	ra, err := retryAfterTime(resp)
	if err != nil && c.Logger != nil {
		c.Logger.Error("setting Retry-After value", zap.Error(err))
	}
	ari.RetryAfter = ra

	return ari, nil
}

// ariEndpoint returns the ARI endpoint URI for the given certificate
// according to the configured CA's directory.
func (c *Client) ariEndpoint(leafCert *x509.Certificate) string {
	if leafCert == nil || leafCert.SerialNumber == nil {
		return ""
	}
	return c.dir.RenewalInfo + "/" + ARIUniqueIdentifier(leafCert)
}

// ARIUniqueIdentifier returns the unique identifier for the certificate
// as used by ACME Renewal Information.
// EXPERIMENTAL: ARI is a draft RFC spec: draft-ietf-acme-ari-03
func ARIUniqueIdentifier(leafCert *x509.Certificate) string {
	return b64NoPad.EncodeToString(leafCert.AuthorityKeyId) + "." +
		b64NoPad.EncodeToString(leafCert.SerialNumber.Bytes())
}

var b64NoPad = base64.URLEncoding.WithPadding(base64.NoPadding)
