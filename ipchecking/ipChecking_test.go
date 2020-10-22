package ipchecking_test

import (
	"testing"

	ipchecking "github.com/tommoulard/fail2ban/ipchecking"
)

func TestIPGeneration(t *testing.T) {
	tests := []struct {
		name     string
		stringIP string
		res      bool
	}{
		{
			name:     "[IP] Valid IP",
			stringIP: "127.0.0.1",
			res:      true,
		},
		{
			name:     "[IP] Invalid IP value 8 first bits",
			stringIP: "25666.0.0.1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IP value 8 second bits",
			stringIP: "127.4444.0.1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IP value 8 third bits",
			stringIP: "127.0.4440.1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IP value 8 last bits",
			stringIP: "127.0.0.1233",
			res:      false,
		},
		{
			name:     "[IP] Invalid CIDR form",
			stringIP: "127.0.0.1/22/34",
			res:      false,
		},
		{
			name:     "[CIDR] Invalid CIDR ",
			stringIP: "127.0.0.1/55",
			res:      false,
		},
		{
			name:     "[CIDR] Missing CIDR ",
			stringIP: "127.0.0.1/",
			res:      false,
		},
		{
			name:     "[CIDR] Valid CIDR ",
			stringIP: "127.0.0.1/23",
			res:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ipchecking.BuildIP(tt.stringIP)
			if (err != nil) == tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, (err == nil))
			}
		})
	}
}

func TestIPChecking(t *testing.T) {
	ip, err := ipchecking.BuildIP("127.0.0.1")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "127.0.0.1", err)
	}
	ip2, err := ipchecking.BuildIP("127.0.0.2")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "127.0.0.1", err)
	}
	cidr1, err := ipchecking.BuildIP("127.0.0.1/24")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "127.0.0.1", err)
	}
	cidr2, err := ipchecking.BuildIP("127.0.1.1/24")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "127.0.0.1", err)
	}

	tests := []struct {
		name     string
		stringIP string
		testedIP ipchecking.IP
		res      bool
	}{
		{
			name:     "[IP] match",
			stringIP: "127.0.0.1",
			testedIP: ip,
			res:      true,
		},
		{
			name:     "[IP] No Match",
			stringIP: "127.0.0.1",
			testedIP: ip2,
			res:      false,
		},
		{
			name:     "[CIDR] No Match",
			stringIP: "127.0.0.1",
			testedIP: cidr2,
			res:      false,
		},
		{
			name:     "[CIDR] Match",
			stringIP: "127.0.0.1",
			testedIP: cidr1,
			res:      true,
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
