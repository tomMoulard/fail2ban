package chain_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
)

type PongHandler struct{}

func (h *PongHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "pong")
}

type Handler struct{}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	d := data.GetData(r)

	fmt.Printf("data: %+v\n", d)

	return nil, nil
}

func Example() {
	// This example shows how to chain handlers together.
	// The final handler is called only if all the previous handlers did not
	// return an error.
	// Create a new chain with a final h.
	h := &Handler{}
	c := chain.New(&PongHandler{}, h)

	// Create a new request.
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)

	// Create a new response recorder.
	rec := httptest.NewRecorder()

	// use the chain
	c.ServeHTTP(rec, req)
	fmt.Println(rec.Body.String())

	// Output:
	// data: &{RemoteIP:192.0.2.1}
	// pong
}
