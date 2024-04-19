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
	"fmt"
	"strings"

	"github.com/mholt/acmez/acme"
)

// MailChallengeReplyGen builds email body with headers to reply MailReply00
// challenge response email. This function only builds the email body; sending the
// message has to be performed by caller of this function.
// mailSubject and messageId come from the challenge mail,
// and if there is no reply-to header in challenge email, replyTo parameter should be ""
func MailChallengeReplyGen(c acme.Challenge, mailSubject string, messageId string, replyTo string) string {
	if len(replyTo) == 0 {
		replyTo = c.From
	}
	mailSubject = strings.TrimPrefix(mailSubject, "ACME: ")
	keyAuth := c.MailReply00KeyAuthorization(mailSubject)
	msg := fmt.Sprint("To: ", replyTo, "\r\n",
		"From:", c.Identifier.Value, "\r\n",
		"In-Reply-To: ", messageId, "\r\n",
		"Subject: RE: ACME: ", mailSubject, "\r\n",
		"Content-Type: text/plain\r\n",
		"\r\n",
		"-----BEGIN ACME RESPONSE-----\r\n",
		keyAuth, "\r\n",
		"-----END ACME RESPONSE-----\r\n",
	)
	return msg
}
