package deny

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	"github.com/tomMoulard/fail2ban/pkg/utils/time"
)

var testHeaderName = "X-Forwarded-For"

var testSourceCriterion = rules.SourceCriterion{
	RequestHeaderName: &testHeaderName,
}

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

			f2b := fail2ban.New(rules.RulesTransformed{}, nil)
			d := New(test.regs, f2b)

			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err := data.ServeHTTP(recorder, req, testSourceCriterion)
			require.NoError(t, err)

			got, err := d.ServeHTTP(recorder, req)
			require.NoError(t, err)
			assert.Equal(t, test.expectedStatus, got)
			require.Equal(t, len(test.expectedIPViewed), len(f2b.IPs))

			// workaround for time.Now() not matching between expected and actual
			for k, v := range test.expectedIPViewed {
				assert.Contains(t, f2b.IPs, k)

				// copy timestamp, as it will not match otherwise. Then compare
				v.Viewed = f2b.IPs[k].Viewed
				assert.Equal(t, v, f2b.IPs[k])
			}
		})
	}
}
