package fail2ban

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	utime "github.com/tomMoulard/fail2ban/pkg/utils/time"
)

func TestShouldAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cfg      *Fail2Ban
		remoteIP string
		expect   assert.BoolAssertionFunc
	}{
		{
			name: "first request",
			cfg: &Fail2Ban{
				IPs: map[string]ipchecking.IPViewed{},
			},
			expect: assert.True,
		},
		{
			name: "second request",
			cfg: &Fail2Ban{
				IPs: map[string]ipchecking.IPViewed{
					"10.0.0.0": {
						Viewed: utime.Now(),
						Count:  1,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   assert.True,
		},
		{
			name: "denylisted request",
			cfg: &Fail2Ban{
				rules: rules.RulesTransformed{
					Bantime: 300 * time.Second,
				},
				IPs: map[string]ipchecking.IPViewed{
					"10.0.0.0": {
						Viewed: utime.Now(),
						Count:  1,
						Denied: true,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   assert.False,
		},
		{
			name: "should unblock request", // since no request during bantime
			cfg: &Fail2Ban{
				rules: rules.RulesTransformed{
					Bantime: 300 * time.Second,
				},
				IPs: map[string]ipchecking.IPViewed{
					"10.0.0.0": {
						Viewed: utime.Now().Add(-600 * time.Second),
						Count:  1,
						Denied: true,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   assert.True,
		},
		{
			name: "should block request", // since too much request during findtime
			cfg: &Fail2Ban{
				rules: rules.RulesTransformed{
					MaxRetry: 1,
					Findtime: 300 * time.Second,
				},
				IPs: map[string]ipchecking.IPViewed{
					"10.0.0.0": {
						Viewed: utime.Now().Add(600 * time.Second),
						Count:  1,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   assert.False,
		},
		{
			name: "should check request",
			cfg: &Fail2Ban{
				rules: rules.RulesTransformed{
					MaxRetry: 3,
					Findtime: 300 * time.Second,
				},
				IPs: map[string]ipchecking.IPViewed{
					"10.0.0.0": {
						Viewed: utime.Now().Add(600 * time.Second),
						Count:  1,
					},
				},
			},
			remoteIP: "10.0.0.0",
			expect:   assert.True,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			allowed := test.cfg.ShouldAllow(context.Background(), test.remoteIP)
			test.expect(t, allowed)
		})
	}
}
