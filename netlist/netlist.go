// Package netlist provides access to the Akamai Network List APIs
package netlist

import (
	"errors"

	"github.com/akamai/AkamaiOPEN-edgegrid-golang/v2/pkg/session"
)

var (
	// ErrStructValidation is returned returned when given struct validation failed
	ErrStructValidation = errors.New("struct validation")
)

type (
	// NETLIST is the netlist api interface
	NETLIST interface {
		NetworkList
	}

	netlist struct {
		session.Session
	}

	// Option defines a PAPI option
	Option func(*netlist)

	// ClientFunc is a netlist client new method, this can used for mocking
	ClientFunc func(sess session.Session, opts ...Option) NETLIST
)

// Client returns a new netlist Client instance with the specified controller
func Client(sess session.Session, opts ...Option) NETLIST {
	n := &netlist{
		Session: sess,
	}

	for _, opt := range opts {
		opt(n)
	}
	return n
}
