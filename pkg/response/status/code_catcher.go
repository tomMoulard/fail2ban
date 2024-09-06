package status

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

// Source: https://github.com/traefik/traefik/blob/05d2c86074a21d482945b9994d85e3b66de0480d/pkg/middlewares/customerrors/custom_errors.go

// codeCatcher is a response writer that detects as soon as possible whether
// the response is a code within the ranges of codes it watches for.
// If it is, it simply drops the data from the response.
// Otherwise, it forwards the data directly to the original client.
// If the backend does not call WriteHeader, we consider it's a 200.
type codeCatcher struct {
	headerMap          http.Header
	code               int
	httpCodeRanges     HTTPCodeRanges
	caughtFilteredCode bool
	responseWriter     http.ResponseWriter
	headersSent        bool

	// bytes is used to store the response body in case of a filtered code that
	// is allowed.
	bytes []byte
	// allowedRequest is there in case of flush when the caughtFilteredCode is
	// set, but the request should be forwarded.
	allowedRequest bool
}

func newCodeCatcher(rw http.ResponseWriter, httpCodeRanges HTTPCodeRanges) *codeCatcher {
	return &codeCatcher{
		headerMap:      make(http.Header),
		code:           http.StatusOK,
		responseWriter: rw,
		httpCodeRanges: httpCodeRanges,
	}
}

func (cc *codeCatcher) Header() http.Header {
	if cc.headersSent {
		return cc.responseWriter.Header()
	}

	if cc.headerMap == nil {
		cc.headerMap = make(http.Header)
	}

	return cc.headerMap
}

func (cc *codeCatcher) getCode() int {
	return cc.code
}

// isFilteredCode returns whether the codeCatcher received a response code
// among the ones it is watching, and for which the response should be deferred
// to the fail2ban handler.
func (cc *codeCatcher) isFilteredCode() bool {
	return cc.caughtFilteredCode
}

func (cc *codeCatcher) Write(buf []byte) (int, error) {
	// If WriteHeader was already called from the caller, this is a NOOP.
	// Otherwise, cc.code is actually a 200 here.
	cc.WriteHeader(cc.code)

	if cc.caughtFilteredCode {
		// We don't care about the contents of the response,
		// since we want to serve the forbidden page,
		// so we just save them for later if needed.
		cc.bytes = append(cc.bytes, buf...)

		return len(buf), nil
	}

	fmt.Printf("Write: buf: %q, code: %d", buf, cc.code)

	i, err := cc.responseWriter.Write(buf)
	if err != nil {
		return i, fmt.Errorf("failed to write to response: %w", err)
	}

	return i, nil
}

// WriteHeader is, in the specific case of 1xx status codes, a direct call to
// the wrapped ResponseWriter, without marking headers as sent, allowing so
// further calls.
func (cc *codeCatcher) WriteHeader(code int) {
	if cc.headersSent || cc.caughtFilteredCode {
		return
	}

	fmt.Printf("Write header: code: %d", code)

	// Handling informational headers.
	if code >= 100 && code <= 199 {
		// Multiple informational status codes can be used,
		// so here the copy is not appending the values to not repeat them.
		for k, v := range cc.Header() {
			cc.responseWriter.Header()[k] = v
		}

		cc.responseWriter.WriteHeader(code)

		return
	}

	cc.code = code
	for _, block := range cc.httpCodeRanges {
		if cc.code >= block[0] && cc.code <= block[1] {
			cc.caughtFilteredCode = true
			// it will be up to the caller to send the headers,
			// so it is out of our hands now.
			return
		}
	}

	// The copy is not appending the values,
	// to not repeat them in case any informational status code has been written.
	for k, v := range cc.Header() {
		cc.responseWriter.Header()[k] = v
	}

	cc.responseWriter.WriteHeader(cc.code)
	cc.headersSent = true
}

// Hijack hijacks the connection.
func (cc *codeCatcher) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := cc.responseWriter.(http.Hijacker); ok {
		conn, rw, err := hj.Hijack()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to hijack connection: %w", err)
		}

		return conn, rw, nil
	}

	return nil, nil, fmt.Errorf("%T is not a http.Hijacker", cc.responseWriter)
}

// Flush sends any buffered data to the client.
func (cc *codeCatcher) Flush() {
	// If WriteHeader was already called from the caller, this is a NOOP.
	// Otherwise, cc.code is actually a 200 here.
	cc.WriteHeader(cc.code)

	fmt.Printf("Flush: code: %d, caughtFilteredCode: %t", cc.code, cc.caughtFilteredCode)

	// We don't care about the contents of the response,
	// since we want to serve the forbidden page,
	// so we just don't flush.
	// (e.g., To prevent superfluous WriteHeader on request with a
	// `Transfert-Encoding: chunked` header).
	if cc.caughtFilteredCode && !cc.allowedRequest {
		return
	}

	if flusher, ok := cc.responseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
