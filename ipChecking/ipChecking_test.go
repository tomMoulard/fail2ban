package ipChecking_test

import (
	"testing"

	ipChecking "github.com/tommoulard/fail2ban/ipChecking"
)

func TestIpChecking(t *testing.T) {
	tests := []struct {
		name     string
		stringIp string
		testedIp ipChecking.Ip
		res      bool
	}{
		{
			name:     "[IP] No match",
			stringIp: "127.0.0.1",
			testedIp: ipChecking.Ip{
				Ip:   (127 << 24) + 1,
				Cidr: 0xFFFFFFFF,
			},
			res: true,
		},
		{
			name:     "[IP] Match",
			stringIp: "127.0.0.1",
			testedIp: ipChecking.Ip{
				Ip:   (127 << 24) + 2,
				Cidr: 0xFFFFFFFF,
			},
			res: false,
		},
		{
			name:     "[CIDR] No Match",
			stringIp: "127.0.0.1",
			testedIp: ipChecking.Ip{
				Ip:   (127 << 24) + 256,
				Cidr: 0xFFFFFF00,
			},
			res: false,
		},
		{
			name:     "[CIDR] Match",
			stringIp: "127.0.0.1",
			testedIp: ipChecking.Ip{
				Ip:   (127 << 24) + 2,
				Cidr: 0xFFFFFF00,
			},
			res: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.testedIp.CheckIpInSubnet(tt.stringIp)
			if r != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r)
			}
		})
	}
}
