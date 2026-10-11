package acme

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewOrderPayloadOmitsResponseFields(t *testing.T) {
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	order := Order{
		Identifiers:    []Identifier{{Type: "dns", Value: "example.com"}},
		NotBefore:      &when,
		NotAfter:       &when,
		Profile:        "classic",
		Replaces:       "abc",
		Status:         "pending",
		Authorizations: []string{"https://ca.example/authz/1"},
		Finalize:       "https://ca.example/finalize",
		Certificate:    "https://ca.example/cert",
	}
	raw, err := json.Marshal(orderPayload(order))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"expires", "authorizations", "finalize", "certificate", "status", "error"} {
		if _, ok := got[key]; ok {
			t.Fatalf("response field %s was included: %s", key, raw)
		}
	}
	if got["profile"] != "classic" || got["replaces"] != "abc" {
		t.Fatalf("request fields: %s", raw)
	}
	if _, ok := got["notBefore"]; !ok {
		t.Fatalf("notBefore missing: %s", raw)
	}
	if _, ok := got["notAfter"]; !ok {
		t.Fatalf("notAfter missing: %s", raw)
	}

	bare, err := json.Marshal(orderPayload(Order{
		Identifiers: []Identifier{{Type: "dns", Value: "example.com"}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"identifiers":[{"type":"dns","value":"example.com"}]}`
	if string(bare) != want {
		t.Fatalf("got %s", bare)
	}
}
