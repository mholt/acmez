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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/mail"
	"strings"
	"testing"

	"github.com/mholt/acmez/v3/acme"
)

func TestMailReplyChallengeResponse(t *testing.T) {
	tokenPart2 := "x6I65YvEk6xC4KV0QMvdJw"                      // token-part2, obtained through JSON response
	thumbprint := "hC4xyXNn8ZDH4yrcp93Zj3qgQs7LyT_GUL45YD7IVMQ" // fake (raw) base64url encoded account public key
	c := acme.Challenge{
		From:             "acmeca@test.example.com",
		Identifier:       acme.Identifier{Type: "email", Value: "client@test.example.com"},
		Token:            tokenPart2,
		KeyAuthorization: fmt.Sprintf("%s.%s", tokenPart2, thumbprint), // with email-reply-00 only 2nd half of token is prefixed
	}
	subject := "ACME: V4nE8NhYh6edBpfQTg5qqQ" // (raw) base64url encoded token-part1

	// simulate decoding / (re)encoding logic to constuct key authorization
	tp1, err := base64.RawURLEncoding.DecodeString("V4nE8NhYh6edBpfQTg5qqQ")
	if err != nil {
		t.Fatal(err)
	}
	tp2, err := base64.RawURLEncoding.DecodeString(tokenPart2)
	if err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(append(tp1, tp2...))
	h := sha256.Sum256([]byte(fmt.Sprintf("%s.%s", token, thumbprint)))
	keyAuthorization := base64.RawURLEncoding.EncodeToString(h[:])
	if keyAuthorization != "Fjt2SD7KoqSt3I6jwgg8ljjkP9Er7h1w0wF0UihvQIU" {
		t.Errorf("expected key authorization to be %q, got %q", "Fjt2SD7KoqSt3I6jwgg8ljjkP9Er7h1w0wF0UihvQIU", keyAuthorization)
	}

	// generate the actual response
	got, err := MailReplyChallengeResponse(c, subject, "messageId", "")
	if err != nil {
		t.Fatal(err)
	}

	// parse the email message
	msg, err := mail.ReadMessage(bytes.NewBufferString(got))
	if err != nil {
		t.Fatal(err)
	}

	// validate email header properties
	if to := msg.Header.Get("to"); to != "acmeca@test.example.com" {
		t.Errorf("expected To to be %q, got %q", "acmeca@test.example.com", to)
	}
	if from := msg.Header.Get("from"); from != "client@test.example.com" {
		t.Errorf("expected from to be %q, got %q", "client@test.example.com", from)
	}
	if replyTo := msg.Header.Get("in-reply-to"); replyTo != "messageId" {
		t.Errorf("expected content type to be %q, got %q", "messageId", replyTo)
	}
	if subject := msg.Header.Get("subject"); subject != "RE: ACME: V4nE8NhYh6edBpfQTg5qqQ" {
		t.Errorf("expected subject to be %q, got %q", "RE: ACME: V4nE8NhYh6edBpfQTg5qqQ", subject)
	}
	if contentType := msg.Header.Get("content-type"); contentType != "text/plain" {
		t.Errorf("expected content type to be %q, got %q", "text/plain", contentType)
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		t.Fatal(err)
	}

	// validate the response
	trimmed, _ := strings.CutPrefix(strings.TrimSpace(string(body)), "-----BEGIN ACME RESPONSE-----")
	trimmed, _ = strings.CutSuffix(trimmed, "-----END ACME RESPONSE-----")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed != "Fjt2SD7KoqSt3I6jwgg8ljjkP9Er7h1w0wF0UihvQIU" {
		t.Errorf("expected ACME challenge response to be %q, got %q", "Fjt2SD7KoqSt3I6jwgg8ljjkP9Er7h1w0wF0UihvQIU", trimmed)
	}
}
