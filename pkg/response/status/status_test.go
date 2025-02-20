package status

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jhalag/fail2ban/pkg/data"
	"github.com/jhalag/fail2ban/pkg/fail2ban"
	"github.com/jhalag/fail2ban/pkg/ipchecking"
	"github.com/jhalag/fail2ban/pkg/rules"
	utime "github.com/jhalag/fail2ban/pkg/utils/time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatus(t *testing.T) {
	t.Parallel()

	body := "Hello, world!"

	tests := []struct {
		name             string
		codeRanges       string
		ips              map[string]ipchecking.IPViewed
		respStatusCode   int
		expectedStatus   int
		expectedIPViewed map[string]ipchecking.IPViewed
		expectedBody     string
	}{
		{
			name:           "already denied", // should not happen as it should already be blocked
			codeRanges:     "400-499",
			respStatusCode: http.StatusBadRequest,
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
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "is being denied",
			codeRanges:     "400-499",
			respStatusCode: http.StatusBadRequest,
			ips: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  42,
					Denied: false,
				},
			},
			expectedIPViewed: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  43,
					Denied: true,
				},
			},
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "not denied in limits",
			codeRanges:     "400-499",
			respStatusCode: http.StatusBadRequest,
			ips:            map[string]ipchecking.IPViewed{},
			expectedIPViewed: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  1,
					Denied: false,
				},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   body,
		},
		{
			name:             "not denied out of limits",
			codeRanges:       "400-499",
			respStatusCode:   http.StatusOK,
			ips:              map[string]ipchecking.IPViewed{},
			expectedIPViewed: map[string]ipchecking.IPViewed{},
			expectedStatus:   http.StatusOK,
			expectedBody:     body,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.NotZero(t, test.respStatusCode)
				w.WriteHeader(test.respStatusCode)
				t.Logf("status code: %d", test.respStatusCode)

				_, err := w.Write([]byte(body))
				assert.NoError(t, err)
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

			var b bytes.Buffer
			recorder = &httptest.ResponseRecorder{Body: &b}
			d.ServeHTTP(recorder, req)
			t.Logf("recorder: %+v", recorder)

			//workaround for time.Now() not matching between expected and actual
			for k, v := range test.expectedIPViewed {
				//equal size maps
				assert.Equal(t, len(test.expectedIPViewed), len(f2b.IPs))

				//expected key exists
				_, ok := f2b.IPs[k]
				assert.True(t, ok)

				//copy timestamp, as it will not match otherwise. Then compare
				v.Viewed = f2b.IPs[k].Viewed
				assert.Equal(t, v, f2b.IPs[k])
			}

			assert.Equal(t, test.expectedStatus, recorder.Code)
			require.NotNil(t, recorder.Body)
			assert.Equal(t, test.expectedBody, recorder.Body.String())
		})
	}
}
