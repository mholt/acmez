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

// MailChallangeReplyGen builds email body with headers to reply MailReply00
// challange Response email. This fucntion just build body, and sendung
// message have to done by caller of this function
// mailSubject and messageId is such from challange mail,
// and if there is no reply-to header in challange email, replyto parametere should be ""
func MailChallangeReplyGen(c acme.Challenge, mailSubject string, messgageId string, replyto string) string {
	if len(replyto) == 0 {
		replyto = c.From
	}
	mailSubject = strings.TrimPrefix(mailSubject, "ACME: ")
	keyauth := c.MailReply00KeyAuthorization(mailSubject)
	msg := fmt.Sprint("To: ", replyto, "\r\n",
		"From:", c.Identifier.Value, "\r\n",
		"In-Reply-To: ", messgageId, "\r\n",
		"Subject: RE: ACME: ", mailSubject, "\r\n",
		"Content-Type: text/plain\r\n",
		"\r\n",
		"-----BEGIN ACME RESPONSE-----\r\n",
		keyauth, "\r\n",
		"-----END ACME RESPONSE-----\r\n",
	)
	return msg
}
