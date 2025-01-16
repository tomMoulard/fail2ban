package allow

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
)

func TestAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		ipList         []string
		expectedStatus *chain.Status
	}{
		{
			name:   "allowed",
			ipList: []string{"192.0.2.1"},
			expectedStatus: &chain.Status{
				Break: true,
			},
		},
		{
			name: "denied",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			a, err := New(test.ipList)
			require.NoError(t, err)

			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err = data.ServeHTTP(recorder, req, "X-Forwarded-For")
			require.NoError(t, err)

			got, err := a.ServeHTTP(recorder, req)
			require.NoError(t, err)
			assert.Equal(t, test.expectedStatus, got)
		})
	}
}
