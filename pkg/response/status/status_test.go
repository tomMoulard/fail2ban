package status

import (
	"bytes"
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
			expectedStatus: http.StatusTooManyRequests,
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
			expectedStatus: http.StatusTooManyRequests,
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
			}, nil)
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

			require.Equal(t, len(test.expectedIPViewed), len(f2b.IPs))

			// workaround for time.Now() not matching between expected and actual
			for k, v := range test.expectedIPViewed {
				assert.Contains(t, f2b.IPs, k)

				// copy timestamp, as it will not match otherwise. Then compare
				v.Viewed = f2b.IPs[k].Viewed
				assert.Equal(t, v, f2b.IPs[k])
			}

			assert.Equal(t, test.expectedStatus, recorder.Code)
			require.NotNil(t, recorder.Body)
			assert.Equal(t, test.expectedBody, recorder.Body.String())
		})
	}
}

func TestHeaderCopying(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		codeRanges     string
		respStatusCode int
		respHeaders    map[string]string
		shouldCopy     bool
		remoteIP       string
		ips            map[string]ipchecking.IPViewed
	}{
		{
			name:           "headers copied for non-filtered status",
			codeRanges:     "400-499",
			respStatusCode: http.StatusOK,
			respHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, POST",
				"Content-Type":                 "application/json",
				"X-Custom-Header":              "test-value",
			},
			shouldCopy: true,
			remoteIP:   "192.0.2.1",
			ips:        map[string]ipchecking.IPViewed{},
		},
		{
			name:           "headers copied for filtered but allowed status",
			codeRanges:     "400-499",
			respStatusCode: http.StatusBadRequest,
			respHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, POST",
				"Content-Type":                 "application/json",
			},
			shouldCopy: true,
			remoteIP:   "192.0.2.1",
			ips:        map[string]ipchecking.IPViewed{},
		},
		{
			name:           "headers not copied for banned IP",
			codeRanges:     "400-499",
			respStatusCode: http.StatusBadRequest,
			respHeaders: map[string]string{
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Methods": "GET, POST",
				"Content-Type":                 "application/json",
			},
			shouldCopy: false,
			remoteIP:   "192.0.2.1",
			ips: map[string]ipchecking.IPViewed{
				"192.0.2.1": {
					Viewed: utime.Now(),
					Count:  42,
					Denied: true,
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			// Create a test handler that returns specific headers
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range test.respHeaders {
					w.Header().Set(k, v)
				}

				w.WriteHeader(test.respStatusCode)
				_, _ = w.Write([]byte("test body"))
			})

			rulesObj := rules.Rules{
				Maxretry:   42,
				StatusCode: test.codeRanges,
				Bantime:    "300s",
				Findtime:   "120s",
				Enabled:    true,
			}
			rulesTransformed, err := rules.TransformRule(rulesObj)
			require.NoError(t, err)

			f2b := fail2ban.New(rulesTransformed, nil)
			// Set IP viewed state
			for ip, viewed := range test.ips {
				f2b.IPs[ip] = viewed
			}

			statusHandler, err := New(next, test.codeRanges, f2b)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req, err = data.ServeHTTP(httptest.NewRecorder(), req)
			require.NoError(t, err)

			d := data.GetData(req)
			d.RemoteIP = test.remoteIP

			recorder := httptest.NewRecorder()
			statusHandler.ServeHTTP(recorder, req)

			// Check if headers were copied as expected
			if test.shouldCopy {
				for k, v := range test.respHeaders {
					assert.Equal(t, v, recorder.Header().Get(k), "Header %s should be copied", k)
				}
			} else {
				// For banned IPs, headers should not be copied
				for k := range test.respHeaders {
					assert.Empty(t, recorder.Header().Get(k), "Header %s should not be copied for banned IP", k)
				}
			}
		})
	}
}
