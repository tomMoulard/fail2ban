// Package chain provides a way to chain multiple http.Handler together.
package chain

import (
	"log"
	"net/http"

	"github.com/tomMoulard/fail2ban/pkg/data"
)

type Status struct {
	Return bool
	Break  bool
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
	handlers []ChainHandler
	final    http.Handler
	status   *http.Handler
}

func New(final http.Handler, handlers ...ChainHandler) Chain {
	return &chain{
		handlers: handlers,
		final:    final,
	}
}

func (c *chain) WithStatus(status http.Handler) {
	c.status = &status
}

// ServeHTTP chains the handlers together, and calls the final handler at the end.
func (c *chain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, err := data.ServeHTTP(w, r)
	if err != nil {
		log.Printf("data.ServeHTTP error: %v", err)

		return
	}

	for _, handler := range c.handlers {
		s, err := handler.ServeHTTP(w, r)
		if err != nil {
			log.Printf("handler.ServeHTTP error: %v", err)

			break
		}

		if s == nil {
			continue
		}

		if s.Return {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		if s.Break {
			break
		}
	}

	if c.status != nil {
		(*c.status).ServeHTTP(w, r)

		return
	}

	c.final.ServeHTTP(w, r)
}
