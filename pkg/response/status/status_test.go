package status

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	utime "github.com/tomMoulard/fail2ban/pkg/utils/time"
)

func TestStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		codeRanges       string
		statusCode       int
		ips              map[string]ipchecking.IPViewed
		expectedStatus   int
		expectedIPViewed map[string]ipchecking.IPViewed
	}{
		{
			name:       "already denied", // should not happen
			codeRanges: "400-499",
			statusCode: http.StatusBadRequest,
			ips: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  42,
					Denied: true,
				},
			},
			expectedIPViewed: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  43,
					Denied: true,
				},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:       "denied next time",
			codeRanges: "400-499",
			statusCode: http.StatusBadRequest,
			ips: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  42,
				},
			},
			expectedIPViewed: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  43,
					Denied: true,
				},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:       "not denied in limits",
			codeRanges: "400-499",
			statusCode: http.StatusBadRequest,
			ips:        map[string]ipchecking.IPViewed{},
			expectedIPViewed: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  1,
					Denied: false,
				},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:             "not denied",
			codeRanges:       "400-499",
			statusCode:       http.StatusOK,
			ips:              map[string]ipchecking.IPViewed{},
			expectedIPViewed: map[string]ipchecking.IPViewed{},
			expectedStatus:   http.StatusOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NotZero(t, test.statusCode)
				w.WriteHeader(test.statusCode)
				t.Logf("status code: %d", test.statusCode)
			})

			f2b := fail2ban.New(rules.RulesTransformed{
				MaxRetry: 1,
				Findtime: 300 * time.Second,
				Bantime:  300 * time.Second,
			})
			f2b.IPs = test.ips
			d, err := New(next, test.codeRanges, f2b)
			require.NoError(t, err)

			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err = data.ServeHTTP(recorder, req)
			require.NoError(t, err)

			d.ServeHTTP(recorder, req)
			t.Logf("recorder: %+v", recorder)

			assert.Equal(t, test.expectedIPViewed, f2b.IPs)
			assert.Equal(t, test.expectedStatus, recorder.Code)
		})
	}
}
