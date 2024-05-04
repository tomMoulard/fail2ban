package deny

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/utils/time"
)

func TestDeny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		regs             []*regexp.Regexp
		expectedStatus   *chain.Status
		expectedIPViewed map[string]ipchecking.IPViewed
	}{
		{
			name: "denied",
			regs: []*regexp.Regexp{regexp.MustCompile(`^https://example.com/foo$`)},
			expectedStatus: &chain.Status{
				Return: true,
			},
			expectedIPViewed: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: time.Now(),
					Count:  1,
					Denied: true,
				},
			},
		},
		{
			name:             "not denied",
			expectedIPViewed: map[string]ipchecking.IPViewed{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			muIP := sync.Mutex{}
			ipViewed := make(map[string]ipchecking.IPViewed)
			d := New(test.regs, &muIP, &ipViewed)

			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err := data.ServeHTTP(recorder, req)
			require.NoError(t, err)

			got, err := d.ServeHTTP(recorder, req)
			require.NoError(t, err)
			assert.Equal(t, test.expectedStatus, got)
			assert.Equal(t, test.expectedIPViewed, ipViewed)
		})
	}
}
