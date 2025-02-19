package chain

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jhalag/fail2ban/pkg/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockHandler struct {
	called         int
	err            error
	expectedCalled int
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.called++
}

func (m *mockHandler) assert(t *testing.T) {
	t.Helper()

	assert.Equal(t, m.expectedCalled, m.called)
}

type mockChainHandler struct {
	mockHandler
	status *Status
}

func (m *mockChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error) {
	m.called++

	return m.status, m.err
}

func (m *mockChainHandler) assert(t *testing.T) {
	t.Helper()

	assert.Equal(t, m.expectedCalled, m.called)
}

func TestChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		finalHandler     *mockHandler
		handlers         []ChainHandler
		expectedStatus   *Status
		expectFinalCount int
	}{
		{
			name:         "return",
			finalHandler: &mockHandler{expectedCalled: 0},
			handlers: []ChainHandler{&mockChainHandler{
				status:      &Status{Return: true},
				mockHandler: mockHandler{expectedCalled: 1},
			}},
			expectedStatus: &Status{
				Return: true,
			},
		},
		{
			name:         "break",
			finalHandler: &mockHandler{expectedCalled: 1},
			handlers: []ChainHandler{&mockChainHandler{
				status:      &Status{Break: true},
				mockHandler: mockHandler{expectedCalled: 1},
			}},
			expectedStatus: &Status{
				Break: true,
			},
		},
		{
			name:         "nil",
			finalHandler: &mockHandler{expectedCalled: 1},
			handlers: []ChainHandler{&mockChainHandler{
				status:      nil,
				mockHandler: mockHandler{expectedCalled: 1},
			}},
		},
		{
			name:         "error",
			finalHandler: &mockHandler{expectedCalled: 1},
			handlers: []ChainHandler{&mockChainHandler{
				mockHandler: mockHandler{
					err:            errors.New("error"),
					expectedCalled: 1,
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := New(test.finalHandler, test.handlers...)
			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err := data.ServeHTTP(recorder, req)
			require.NoError(t, err)

			c.ServeHTTP(recorder, req)

			test.finalHandler.assert(t)

			for _, handler := range test.handlers {
				mch, ok := handler.(*mockChainHandler)
				require.True(t, ok)
				mch.assert(t)
			}
		})
	}
}

type mockChainOrderHandler struct {
	status int
}

var countOrder int

func (m *mockChainOrderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error) {
	m.status = countOrder
	countOrder++

	return nil, nil
}

func TestChainOrder(t *testing.T) {
	t.Parallel()

	a := &mockChainOrderHandler{}
	b := &mockChainOrderHandler{}
	c := &mockChainOrderHandler{}
	final := &mockHandler{
		expectedCalled: 1,
	}

	ch := New(final, a, b, c)
	r := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	ch.ServeHTTP(nil, r)

	assert.Equal(t, 0, a.status)
	assert.Equal(t, 1, b.status)
	assert.Equal(t, 2, c.status)
	final.assert(t)
}

type mockDataHandler struct {
	t          *testing.T
	ExpectData *data.Data
}

func (m *mockDataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error) {
	d := data.GetData(r)
	assert.Equal(m.t, m.ExpectData, d)

	return nil, nil
}

func TestChainRequestContext(t *testing.T) {
	t.Parallel()

	handler := &mockDataHandler{
		t:          t,
		ExpectData: &data.Data{RemoteIP: "192.0.2.1"},
	}

	final := &mockHandler{
		expectedCalled: 1,
	}

	ch := New(final, handler)
	r := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	ch.ServeHTTP(nil, r)

	final.assert(t)
}

func TestChainWithStatus(t *testing.T) {
	t.Parallel()

	handler := &mockChainHandler{
		mockHandler: mockHandler{expectedCalled: 1},
	}
	final := &mockHandler{expectedCalled: 0}
	status := &mockHandler{expectedCalled: 1}

	ch := New(final, handler)
	ch.WithStatus(status)

	r := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	ch.ServeHTTP(nil, r)

	handler.assert(t)
	final.assert(t)
	status.assert(t)
}
