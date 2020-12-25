// Package appsec provides access to the Akamai Security Application APIs
package appsec

import (
	"errors"
	"net/http"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v2/pkg/session"
)

var (
	// ErrStructValidation is returned returned when given struct validation failed
	ErrStructValidation = errors.New("struct validation")

	// ErrNotFound is returned when requested resource was not found
	ErrNotFound = errors.New("resource not found")
)

type (
	// APPSEC is the papi api interface
	APPSEC interface {
		Configs
		ConfigVersions
		Rules
		Policy
	}

	appsec struct {
		session.Session
		usePrefixes bool
	}

	// Option defines a APPSEC option
	Option func(*appsec)

	// ClientFunc is a appsec client new method, this can used for mocking
	ClientFunc func(sess session.Session, opts ...Option) APPSEC

	// Response is a base APPSEC Response type
	Response struct {
		AccountID  string   `json:"omitempty"`
		ContractID string   `json:"contractId,omitempty"`
		GroupID    string   `json:"groupId,omitempty"`
		Etag       string   `json:"etag,omitempty"`
		Errors     []*Error `json:"errors,omitempty"`
		Warnings   []*Error `json:"warnings,omitempty"`
	}
)

// Client returns a new appsec Client instance with the specified controller
func Client(sess session.Session, opts ...Option) APPSEC {
	a := &appsec{
		Session:     sess,
		usePrefixes: true,
	}

	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Exec overrides the session.Exec to add papi options
func (p *appsec) Exec(r *http.Request, out interface{}, in ...interface{}) (*http.Response, error) {
	return p.Session.Exec(r, out, in...)
}
