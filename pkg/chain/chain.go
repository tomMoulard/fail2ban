// Package chain provides a way to chain multiple http.Handler together.
package chain

import (
	"log"
	"net/http"

	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/rules"
)

// Status is a status that can be returned by a handler.
type Status struct {
	// Return is a flag that tells the chain to return. If Return is true, the
	// chain will return a 403 (e.g., the ip is in the denylist)
	Return bool
	// Break is a flag that tells the chain to break. If Break is true, the chain
	// will stop (e.g., the ip is in the allowlist)
	Break bool
}

// ChainHandler is a handler that can be chained.
type ChainHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error)
}

// Chain is a chain of handlers.
type Chain interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	WithStatus(status http.Handler)
}

type chain struct {
	handlers        []ChainHandler
	final           http.Handler
	status          *http.Handler
	sourceCriterion rules.SourceCriterion
}

// New creates a new chain.
func New(final http.Handler, sourceCriterion rules.SourceCriterion, handlers ...ChainHandler) Chain {
	return &chain{
		handlers:        handlers,
		final:           final,
		sourceCriterion: sourceCriterion,
	}
}

// WithStatus sets the status handler.
func (c *chain) WithStatus(status http.Handler) {
	c.status = &status
}

// ServeHTTP chains the handlers together, and calls the final handler at the end.
func (c *chain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req, err := data.ServeHTTP(w, r, c.sourceCriterion)
	if err != nil {
		log.Printf("data.ServeHTTP error: %v", err)

		return
	}

	for _, handler := range c.handlers {
		s, err := handler.ServeHTTP(w, req)
		if err != nil {
			log.Printf("handler.ServeHTTP error: %v", err)

			break
		}

		if s == nil {
			continue
		}

		if s.Return {
			w.WriteHeader(http.StatusTooManyRequests)

			return
		}

		if s.Break {
			break
		}
	}

	if c.status != nil {
		(*c.status).ServeHTTP(w, req)

		return
	}

	c.final.ServeHTTP(w, req)
}
