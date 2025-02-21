package allow

import (
	"net/http"
	"net/http/httptest"
	"regexp"
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
		regs           []*regexp.Regexp
		expectedStatus *chain.Status
	}{
		{
			name: "allowed",
			regs: []*regexp.Regexp{regexp.MustCompile(`^https://example.com/foo$`)},
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

			a := New(test.regs)

			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err := data.ServeHTTP(recorder, req)
			require.NoError(t, err)

			got, err := a.ServeHTTP(recorder, req)
			require.NoError(t, err)
			assert.Equal(t, test.expectedStatus, got)
		})
	}
}
