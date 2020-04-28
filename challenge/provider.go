package challenge

import (
	"context"
	"time"
)

// Info contains information needed to solve a challenge.
type Info struct {
	Domain  string
	Token   string
	KeyAuth string
}

// Provider enables implementing a custom challenge
// provider. Present presents the solution to a challenge available to
// be solved. CleanUp will be called by the challenge if Present ends
// in a non-error state.
type Provider interface {
	Present(context.Context, Info) error
	CleanUp(context.Context, Info) error
}

// ProviderTimeout allows for implementing a
// Provider where an unusually long timeout is required when
// waiting for an ACME challenge to be satisfied, such as when
// checking for DNS record propagation. If an implementor of a
// Provider provides a Timeout method, then the return values
// of the Timeout method will be used when appropriate by the acme
// package. The interval value is the time between checks.
//
// The default values used for timeout and interval are 60 seconds and
// 2 seconds respectively. These are used when no Timeout method is
// defined for the Provider.
type ProviderTimeout interface {
	Provider
	Timeout() (timeout, interval time.Duration)
}
