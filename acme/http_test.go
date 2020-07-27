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
	"net/http"
	"reflect"
	"testing"
)

func TestExtractLinks(t *testing.T) {
	// Original test code by Isaac (https://github.com/eggsampler/acme)

	linkTests := []struct {
		Name         string
		LinkHeaders  []string
		WantedLink   string
		ExpectedURLs []string
	}{
		{
			Name:         "no links",
			WantedLink:   "fail",
			ExpectedURLs: nil,
		},
		{Name: "joined links",
			LinkHeaders:  []string{`<https://url/path>; rel="next", <http://url/path?query>; rel="up"`},
			WantedLink:   "up",
			ExpectedURLs: []string{"http://url/path?query"},
		},
		{
			Name:         "separate links",
			LinkHeaders:  []string{`<https://url/path>; rel="next"`, `<http://url/path?query>; rel="up"`},
			WantedLink:   "up",
			ExpectedURLs: []string{"http://url/path?query"},
		},
	}
	for _, currentTest := range linkTests {
		linkURLs := extractLinks(&http.Response{Header: http.Header{"Link": currentTest.LinkHeaders}}, currentTest.WantedLink)
		if !reflect.DeepEqual(linkURLs, currentTest.ExpectedURLs) {
			t.Fatalf("%s: links not equal, expected: %s, got: %s", currentTest.Name, currentTest.ExpectedURLs, linkURLs)
		}
	}
}
