package ipchecking_test

import (
	"testing"

	ipchecking "github.com/tomMoulard/fail2ban/ipchecking"
)

func TestIPGeneration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		stringIP string
		res      bool
	}{
		{
			name:     "Valid IPv4",
			stringIP: "127.0.0.1",
			res:      true,
		},
		{
			name:     "Invalid IPv4 value 8 first bits",
			stringIP: "25666.0.0.1",
			res:      false,
		},
		{
			name:     "Invalid IPv4 value 8 second bits",
			stringIP: "127.4444.0.1",
			res:      false,
		},
		{
			name:     "Invalid IPv4 value 8 third bits",
			stringIP: "127.0.4440.1",
			res:      false,
		},
		{
			name:     "Invalid IPv4 value 8 last bits",
			stringIP: "127.0.0.1233",
			res:      false,
		},
		{
			name:     "Invalid IPv4 CIDR form",
			stringIP: "127.0.0.1/22/34",
			res:      false,
		},
		{
			name:     "Invalid IPv4 CIDR ",
			stringIP: "127.0.0.1/55",
			res:      false,
		},
		{
			name:     "Missing IPv4 CIDR ",
			stringIP: "127.0.0.1/",
			res:      false,
		},
		{
			name:     "Valid IPv4 CIDR ",
			stringIP: "127.0.0.1/23",
			res:      true,
		},
		{
			name:     "Valid IPv6",
			stringIP: "::1",
			res:      true,
		},
		{
			name:     "Invalid IPv6 value 8 first bits",
			stringIP: "2566634::1",
			res:      false,
		},
		{
			name:     "Invalid IPv6 value 8 second bits",
			stringIP: "127:444234564:0::1",
			res:      false,
		},
		{
			name:     "Invalid IPv6 value 8 third bits",
			stringIP: "1::4440345::1",
			res:      false,
		},
		{
			name:     "Invalid IPv6 value 8 last bits",
			stringIP: "::34561233",
			res:      false,
		},
		{
			name:     "Invalid IPv6 CIDR form",
			stringIP: "::1/22/34",
			res:      false,
		},
		{
			name:     "Invalid IPv6 CIDR ",
			stringIP: "::1/234",
			res:      false,
		},
		{
			name:     "Missing IPv6 CIDR ",
			stringIP: "::1/",
			res:      false,
		},
		{
			name:     "Valid IPv6 CIDR ",
			stringIP: "::1/53",
			res:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ipchecking.ParseNetIP(tt.stringIP)
			if (err != nil) == tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, (err == nil))
			}
		})
	}
}

func helpBuildIP(t *testing.T, ip string) ipchecking.NetIP {
	t.Helper()

	nip, err := ipchecking.ParseNetIP(ip)
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", nip, err)
	}

	return nip
}

func TestIPChecking(t *testing.T) {
	t.Parallel()

	ipv4 := helpBuildIP(t, "127.0.0.1")
	ipv42 := helpBuildIP(t, "127.0.0.2")
	cidrv41 := helpBuildIP(t, "127.0.0.1/24")
	cidrv42 := helpBuildIP(t, "127.0.1.1/24")

	ipv6 := helpBuildIP(t, "::1")
	ipv62 := helpBuildIP(t, "::2")
	cidrv61 := helpBuildIP(t, "::1/124")
	cidrv62 := helpBuildIP(t, "::1:1/124")

	tests := []struct {
		name     string
		stringIP string
		testedIP ipchecking.NetIP
		res      bool
	}{
		{
			name:     "IPv4 match",
			stringIP: "127.0.0.1",
			testedIP: ipv4,
			res:      true,
		},
		{
			name:     "IPv4 No Match",
			stringIP: "127.0.0.1",
			testedIP: ipv42,
			res:      false,
		},
		{
			name:     "IPv4 No Match",
			stringIP: "127.0.0.1",
			testedIP: cidrv42,
			res:      false,
		},
		{
			name:     "IPv4 Match",
			stringIP: "127.0.0.1",
			testedIP: cidrv41,
			res:      true,
		},
		{
			name:     "IPv6 match",
			stringIP: "::1",
			testedIP: ipv6,
			res:      true,
		},
		{
			name:     "IPv6 No Match",
			stringIP: "::1",
			testedIP: ipv62,
			res:      false,
		},
		{
			name:     "IPv6 No Match",
			stringIP: "::1",
			testedIP: cidrv62,
			res:      false,
		},
		{
			name:     "IPv6 Match",
			stringIP: "::1",
			testedIP: cidrv61,
			res:      true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := tt.testedIP.Contains(tt.stringIP)
			if r != tt.res {
				t.Errorf("wanted '%v' got '%v'", tt.res, r)
			}
		})
	}
}

func TestIPtoString(t *testing.T) {
	t.Parallel()

	ipv4, err := ipchecking.ParseNetIP("127.0.0.1/32")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "127.0.0.1", err)
	}

	ipv6, err := ipchecking.ParseNetIP("::1/128")
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", "::1", err)
	}

	tests := []struct {
		name     string
		testedIP string
		stringIP ipchecking.NetIP
		res      bool
	}{
		{
			name:     "Valid IPv4 string",
			testedIP: "127.0.0.1/32",
			stringIP: ipv4,
			res:      true,
		},
		{
			name:     "Invalid IPv4 string",
			testedIP: "127.0.0.2/32",
			stringIP: ipv4,
			res:      false,
		},
		{
			name:     "Valid IPv6 string",
			testedIP: "::1/128",
			stringIP: ipv6,
			res:      true,
		},
		{
			name:     "Invalid IPv6 string",
			testedIP: "::2/128",
			stringIP: ipv6,
			res:      false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := tt.stringIP.String()
			if (r == tt.testedIP) != tt.res {
				t.Errorf("wanted '%v' got '%v' (when testing %q == %q)",
					tt.res, r == tt.testedIP, r, tt.testedIP)
			}
		})
	}
}
