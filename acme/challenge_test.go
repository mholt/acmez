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
	"testing"
)

func TestChallenge_DNSAccount01TXTRecordName(t *testing.T) {
	tests := []struct {
		name       string
		account    Account
		identifier Identifier
		expected   string
	}{
		{
			name:       "standard account location",
			account:    Account{Location: "https://acme-v02.api.letsencrypt.org/acme/acct/12345"},
			identifier: Identifier{Type: "dns", Value: "example.com"},
			expected:   "_lvrajhh53e27yh7f._acme-challenge.example.com",
		},
		{
			name:       "different account location",
			account:    Account{Location: "https://example.com/acme/account/67890"},
			identifier: Identifier{Type: "dns", Value: "test.example.org"},
			expected:   "_pbvtvcg2uxbmkni3._acme-challenge.test.example.org",
		},
		{
			name:       "empty account location",
			account:    Account{Location: ""},
			identifier: Identifier{Type: "dns", Value: "sub.domain.net"},
			expected:   "_4oymiquy7qobjgx3._acme-challenge.sub.domain.net",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := Challenge{
				Identifier: test.identifier,
			}
			got := c.DNSAccount01TXTRecordName(test.account)
			if got != test.expected {
				t.Errorf("DNSAccount01TXTRecordName() = %q, want %q", got, test.expected)
			}
		})
	}
}
