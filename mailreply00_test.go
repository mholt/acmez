// Copyright 2023 Matthew Holt
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
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"testing"

	"github.com/mholt/acmez/v2/acme"
)

func TestMailReplyChallengeResponse(t *testing.T) {
	tokenPart2 := "mGVIRa3ZTr3TPSUN"                            // token-part2, obtained through JSON response
	thumbprint := "e3xcaXlZ7Ur9xZzIuRDt9dP2r5xspalWFCDfjCbFkzg" // fake (raw) base64url encoded account public key
	c := acme.Challenge{
		From:             "acmeca@test.example.com",
		Identifier:       acme.Identifier{Type: "email", Value: "client@test.example.com"},
		Token:            tokenPart2,
		KeyAuthorization: fmt.Sprintf("%s.%s", tokenPart2, thumbprint), // with email-reply-00 only 2nd half of token is prefixed
	}
	subject := "ACME: dmlxbmw5d2xjT05zWVFGNw" // (raw) base64url encoded token-part1
	got, err := MailReplyChallengeResponse(c, subject, "messageId", "")
	if err != nil {
		t.Fatal(err)
	}

	msg, err := mail.ReadMessage(bytes.NewBufferString(got))
	if err != nil {
		t.Fatal(err)
	}

	if to := msg.Header.Get("to"); to != "acmeca@test.example.com" {
		t.Errorf("expected To to be %q, got %q", "acmeca@test.example.com", to)
	}
	if from := msg.Header.Get("from"); from != "client@test.example.com" {
		t.Errorf("expected from to be %q, got %q", "client@test.example.com", from)
	}
	if replyTo := msg.Header.Get("in-reply-to"); replyTo != "messageId" {
		t.Errorf("expected content type to be %q, got %q", "messageId", replyTo)
	}
	if subject := msg.Header.Get("subject"); subject != "RE: ACME: dmlxbmw5d2xjT05zWVFGNw" {
		t.Errorf("expected subject to be %q, got %q", "RE: ACME: dmlxbmw5d2xjT05zWVFGNw", subject)
	}
	if contentType := msg.Header.Get("content-type"); contentType != "text/plain" {
		t.Errorf("expected content type to be %q, got %q", "text/plain", contentType)
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatal(err)
	}

	trimmed, _ := strings.CutPrefix(strings.TrimSpace(string(body)), "-----BEGIN ACME RESPONSE-----")
	trimmed, _ = strings.CutSuffix(trimmed, "-----END ACME RESPONSE-----")
	trimmed = strings.TrimSpace(trimmed)

	if trimmed != "zPVRe74iorifByo5uXwIgNHOasxE2XHm84f3js1HVmE" {
		t.Errorf("expected ACME challenge response to be %q, got %q", "zPVRe74iorifByo5uXwIgNHOasxE2XHm84f3js1HVmE", trimmed)
	}
}
