package deny

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	utime "github.com/tomMoulard/fail2ban/pkg/utils/time"
)

func TestDeny(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
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
					Viewed: utime.Now(),
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

			f2b := fail2ban.New(ctx, rules.RulesTransformed{
				Bantime:  time.Hour,
				Findtime: time.Hour,
				MaxRetry: 3,
			}, nil, nil)
			d := New(test.regs, f2b)

			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err := data.ServeHTTP(recorder, req)
			require.NoError(t, err)

			got, err := d.ServeHTTP(recorder, req)
			require.NoError(t, err)
			assert.Equal(t, test.expectedStatus, got)
			assert.Equal(t, test.expectedIPViewed, f2b.IPs)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	transformedRules, err := rules.TransformRule(rules.Rules{
		Bantime:  "300s",
		Findtime: "120s",
		Enabled:  true,
	})

	if err != nil {
		t.Fatal(err)
	}

	f2b := fail2ban.New(ctx, transformedRules, nil, nil)
	if f2b == nil {
		t.Error("fail2ban instance should not be nil")
	}
}
