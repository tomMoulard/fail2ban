package ipchecking_test

import (
	"testing"

	ipchecking "github.com/tomMoulard/fail2ban/ipchecking"
)

func TestIPv4Generation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		stringIP string
		res      bool
	}{
		{
			name:     "[IP] Valid IPv4",
			stringIP: "127.0.0.1",
			res:      true,
		},
		{
			name:     "[IP] Invalid IPv4 value 8 first bits",
			stringIP: "25666.0.0.1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv4 value 8 second bits",
			stringIP: "127.4444.0.1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv4 value 8 third bits",
			stringIP: "127.0.4440.1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv4 value 8 last bits",
			stringIP: "127.0.0.1233",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv4 CIDR form",
			stringIP: "127.0.0.1/22/34",
			res:      false,
		},
		{
			name:     "[CIDR] Invalid IPv4 CIDR ",
			stringIP: "127.0.0.1/55",
			res:      false,
		},
		{
			name:     "[CIDR] Missing IPv4 CIDR ",
			stringIP: "127.0.0.1/",
			res:      false,
		},
		{
			name:     "[CIDR] Valid IPv4 CIDR ",
			stringIP: "127.0.0.1/23",
			res:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ipchecking.BuildIP(tt.stringIP)
			if (err != nil) == tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, (err == nil))
			}
		})
	}
}

func TestIPv6Generation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		stringIP string
		res      bool
	}{
		{
			name:     "[IP] Valid IPv6",
			stringIP: "::1",
			res:      true,
		},
		{
			name:     "[IP] Invalid IPv6 value 8 first bits",
			stringIP: "2566634::1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv6 value 8 second bits",
			stringIP: "127:444234564:0::1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv6 value 8 third bits",
			stringIP: "1::4440345::1",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv6 value 8 last bits",
			stringIP: "::34561233",
			res:      false,
		},
		{
			name:     "[IP] Invalid IPv6 CIDR form",
			stringIP: "::1/22/34",
			res:      false,
		},
		{
			name:     "[CIDR] Invalid IPv6 CIDR ",
			stringIP: "::1/234",
			res:      false,
		},
		{
			name:     "[CIDR] Missing IPv6 CIDR ",
			stringIP: "::1/",
			res:      false,
		},
		{
			name:     "[CIDR] Valid IPv6 CIDR ",
			stringIP: "::1/53",
			res:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ipchecking.BuildIP(tt.stringIP)
			if (err != nil) == tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, (err == nil))
			}
		})
	}
}

func TestIPv4Checking(t *testing.T) {
	t.Parallel()
	ip, err := ipchecking.BuildIP("127.0.0.1")
	if err != nil {
		t.Errorf("Error in IPv4 building: %s, with err %v", "127.0.0.1", err)
	}
	ip2, err := ipchecking.BuildIP("127.0.0.2")
	if err != nil {
		t.Errorf("Error in IPv4 building: %s, with err %v", "127.0.0.1", err)
	}
	cidr1, err := ipchecking.BuildIP("127.0.0.1/24")
	if err != nil {
		t.Errorf("Error in IPv4 building: %s, with err %v", "127.0.0.1", err)
	}
	cidr2, err := ipchecking.BuildIP("127.0.1.1/24")
	if err != nil {
		t.Errorf("Error in IPv4 building: %s, with err %v", "127.0.0.1", err)
	}

	tests := []struct {
		name     string
		stringIP string
		testedIP ipchecking.IP
		res      bool
	}{
		{
			name:     "[IP] IPv4 match",
			stringIP: "127.0.0.1",
			testedIP: ip,
			res:      true,
		},
		{
			name:     "[IP] IPv4 No Match",
			stringIP: "127.0.0.1",
			testedIP: ip2,
			res:      false,
		},
		{
			name:     "[CIDR] IPv4 No Match",
			stringIP: "127.0.0.1",
			testedIP: cidr2,
			res:      false,
		},
		{
			name:     "[CIDR] IPv4 Match",
			stringIP: "127.0.0.1",
			testedIP: cidr1,
			res:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := tt.testedIP.CheckIPInSubnet(tt.stringIP)
			if r != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r)
			}
		})
	}
}

func TestIPv6Checking(t *testing.T) {
	t.Parallel()
	ip, err := ipchecking.BuildIP("::1")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "::1", err)
	}
	ip2, err := ipchecking.BuildIP("::2")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "::1", err)
	}
	cidr1, err := ipchecking.BuildIP("::1/124")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "::1/24", err)
	}
	cidr2, err := ipchecking.BuildIP("::1:1/124")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "::1:1/24", err)
	}

	tests := []struct {
		name     string
		stringIP string
		testedIP ipchecking.IP
		res      bool
	}{
		{
			name:     "[IP] IPv6 match",
			stringIP: "::1",
			testedIP: ip,
			res:      true,
		},
		{
			name:     "[IP] IPv6 No Match",
			stringIP: "::1",
			testedIP: ip2,
			res:      false,
		},
		{
			name:     "[CIDR] IPv6 No Match",
			stringIP: "::1",
			testedIP: cidr2,
			res:      false,
		},
		{
			name:     "[CIDR] IPv6 Match",
			stringIP: "::1",
			testedIP: cidr1,
			res:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := tt.testedIP.CheckIPInSubnet(tt.stringIP)
			if r != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r)
			}
		})
	}
}

func TestIPv4toString(t *testing.T) {
	t.Parallel()

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
			name:     "[IP] Valid IPv4 string",
			testedIP: "127.0.0.1/32",
			stringIp: ip,
			res:      true,
		},
		{
			name:     "[IP] Invalid IPv4 string",
			testedIP: "127.0.0.2/32",
			stringIp: ip,
			res:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := tt.stringIp.ToString()
			if (r == tt.testedIP) != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r == tt.testedIP)
			}
		})
	}
}

func TestIPv6toString(t *testing.T) {
	t.Parallel()

	ip, err := ipchecking.BuildIP("::1")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "::1", err)
	}
	tests := []struct {
		name     string
		testedIP string
		stringIp ipchecking.IP
		res      bool
	}{
		{
			name:     "[IP] Valid IPv6 string",
			testedIP: "::1/128",
			stringIp: ip,
			res:      true,
		},
		{
			name:     "[IP] Invalid IPv6 string",
			testedIP: "::2/128",
			stringIp: ip,
			res:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := tt.stringIp.ToString()
			if (r == tt.testedIP) != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r == tt.testedIP)
			}
		})
	}
}
