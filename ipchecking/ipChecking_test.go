package ipchecking_test

import (
	"testing"

	ipchecking "github.com/tommoulard/fail2ban/ipchecking"
)

func TestIPChecking(t *testing.T) {
	tests := []struct {
		name     string
		stringIP string
		testedIP ipchecking.IP
		res      bool
	}{
		{
			name:     "[IP] Valid IP",
			stringIP: "127.0.0.1",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 1,
				Cidr: 0xFFFFFFFF,
			},
			res: true,
		},
		{
			name:     "[IP] Invalid IP value",
			stringIP: "25666.0.0.1",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 1,
				Cidr: 0xFFFFFFFF,
			},
			res: false,
		},
		{
			name:     "[IP] Invalid CIDR form",
			stringIP: "127.0.0.1/22/34",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 256,
				Cidr: 0xFFFFFF00,
			},
			res: false,
		},
		{
			name:     "[IP] No match",
			stringIP: "127.0.0.1",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 1,
				Cidr: 0xFFFFFFFF,
			},
			res: true,
		},
		{
			name:     "[IP] Match",
			stringIP: "127.0.0.1",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 2,
				Cidr: 0xFFFFFFFF,
			},
			res: false,
		},
		{
			name:     "[CIDR] Invalid CIDR ",
			stringIP: "127.0.0.1/55",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 256,
				Cidr: 0xFFFFFF00,
			},
			res: false,
		},
		{
			name:     "[CIDR] No Match",
			stringIP: "127.0.0.1",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 256,
				Cidr: 0xFFFFFF00,
			},
			res: false,
		},
		{
			name:     "[CIDR] Match",
			stringIP: "127.0.0.1",
			testedIP: ipchecking.IP{
				IP:   (127 << 24) + 2,
				Cidr: 0xFFFFFF00,
			},
			res: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.testedIP.CheckIPInSubnet(tt.stringIP)
			if r != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r)
			}
		})
	}
}

func TestIPtoString(t *testing.T) {
	ip, err := ipchecking.BuildIP("127.0.0.1")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "127.0.0.1", err)
	}
	tests := []struct {
		name     string
		testedIP string
		stringIp ipchecking.IP
		res      bool
	}{
		{
			name:     "[IP] Valid IP string",
			testedIP: "127.0.0.1",
			stringIp: ip,
			res:      true,
		},
		{
			name:     "[IP] Invalid IP string",
			testedIP: "127.0.0.2",
			stringIp: ip,
			res:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.stringIp.ToString()
			if (r == tt.testedIP) != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r == tt.testedIP)
			}
		})
	}
}
