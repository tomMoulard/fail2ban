package ipchecking_test

import (
	"fmt"
	"testing"

	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
)

//nolint:dupword
func Example() {
	// Parse multiple IPs/CIDRS
	ips, err := ipchecking.ParseNetIPs([]string{
		"127.0.0.1",
		"10.0.0.0/24", // 10.0.0.1-10.0.0.254
		"::1",
		"2001:db8::/32",
	})
	if err != nil {
		panic(err)
	}

	// Check if an IP is either in the list, or in the list networks
	fmt.Println(ips.Contains(""))                        // false (empty string is not an IP)
	fmt.Println(ips.Contains("127.0.0.1"))               // true
	fmt.Println(ips.Contains("127.0.0.2"))               // false
	fmt.Println(ips.Contains("10.0.0.42"))               // true
	fmt.Println(ips.Contains("::1"))                     // true
	fmt.Println(ips.Contains("2001:db8:beba:cafe::1:2")) // true
	fmt.Println(ips.Contains("64:ff9b::127.0.0.1"))      // false

	// Output:
	// false
	// true
	// false
	// true
	// true
	// true
	// false
}

func TestNetIPParseNetIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		stringIP string
		res      bool
	}{
		{
			name:     "Valid IPv4",
			stringIP: "127.0.0.1",
			res:      false,
		},
		{
			name:     "Invalid IPv4 value 8 first bits",
			stringIP: "25666.0.0.1",
			res:      true,
		},
		{
			name:     "Invalid IPv4 value 8 second bits",
			stringIP: "127.4444.0.1",
			res:      true,
		},
		{
			name:     "Invalid IPv4 value 8 third bits",
			stringIP: "127.0.4440.1",
			res:      true,
		},
		{
			name:     "Invalid IPv4 value 8 last bits",
			stringIP: "127.0.0.1233",
			res:      true,
		},
		{
			name:     "Invalid IPv4 CIDR form",
			stringIP: "127.0.0.1/22/34",
			res:      true,
		},
		{
			name:     "Invalid IPv4 CIDR ",
			stringIP: "127.0.0.1/55",
			res:      true,
		},
		{
			name:     "Missing IPv4 CIDR ",
			stringIP: "127.0.0.1/",
			res:      true,
		},
		{
			name:     "Valid IPv4 CIDR ",
			stringIP: "127.0.0.1/23",
			res:      false,
		},
		{
			name:     "Valid IPv6",
			stringIP: "::1",
			res:      false,
		},
		{
			name:     "Invalid IPv6 value 8 first bits",
			stringIP: "2566634::1",
			res:      true,
		},
		{
			name:     "Invalid IPv6 value 8 second bits",
			stringIP: "127:444234564:0::1",
			res:      true,
		},
		{
			name:     "Invalid IPv6 value 8 third bits",
			stringIP: "1::4440345::1",
			res:      true,
		},
		{
			name:     "Invalid IPv6 value 8 last bits",
			stringIP: "::34561233",
			res:      true,
		},
		{
			name:     "Invalid IPv6 CIDR form",
			stringIP: "::1/22/34",
			res:      true,
		},
		{
			name:     "Invalid IPv6 CIDR ",
			stringIP: "::1/234",
			res:      true,
		},
		{
			name:     "Missing IPv6 CIDR ",
			stringIP: "::1/",
			res:      true,
		},
		{
			name:     "Valid IPv6 CIDR ",
			stringIP: "::1/53",
			res:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ipchecking.ParseNetIP(test.stringIP)
			if test.res != (err != nil) {
				t.Errorf("ParseNetIP() = %v, want %v", err, test.res)
			}
		})
	}
}

func TestNetIPParseNetIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ips         []string
		expectedIPs []string
		expectErr   bool
	}{
		{
			name:        "valid IPv4",
			ips:         []string{"127.0.0.1", "127.0.0.2"},
			expectedIPs: []string{"127.0.0.1", "127.0.0.2"},
			expectErr:   false,
		},
		{
			name:        "valid IPv6",
			ips:         []string{"::1", "::2"},
			expectedIPs: []string{"::1", "::2"},
			expectErr:   false,
		},
		{
			name:      "invalid IPv4",
			ips:       []string{"127.0.0.1.1", "127.0.0.2.42"},
			expectErr: true,
		},
		{
			name:      "invalid IPv6",
			ips:       []string{"::1", "::2::42:"},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ipchecking.ParseNetIPs(test.ips)
			if test.expectErr != (err != nil) {
				t.Errorf("ParseNetIPs() = %v, want %v", err, test.expectErr)
			}

			for i, gotIP := range got {
				if test.expectedIPs[i] != gotIP.String() {
					t.Errorf("ParseNetIPs() = %q, want %q", gotIP.String(), test.expectedIPs[i])
				}
			}
		})
	}
}

func helpParseNetIP(t *testing.T, ip string) ipchecking.NetIP {
	t.Helper()

	nip, err := ipchecking.ParseNetIP(ip)
	if err != nil {
		t.Errorf("Error in IP building: %s, with err %v", nip, err)
	}

	return nip
}

func TestNetIPContains(t *testing.T) {
	t.Parallel()

	ipv4 := helpParseNetIP(t, "127.0.0.1")
	ipv42 := helpParseNetIP(t, "127.0.0.2")
	cidrv41 := helpParseNetIP(t, "127.0.0.1/24")
	cidrv42 := helpParseNetIP(t, "127.0.1.1/24")

	ipv6 := helpParseNetIP(t, "::1")
	ipv62 := helpParseNetIP(t, "::2")
	cidrv61 := helpParseNetIP(t, "::1/124")
	cidrv62 := helpParseNetIP(t, "::1:1/124")

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
		{
			name:     "invalid IPv4",
			stringIP: "127.0.0.1.42",
			testedIP: cidrv41,
			res:      false,
		},
		{
			name:     "invalid IPv6",
			stringIP: "::1::",
			testedIP: cidrv61,
			res:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := test.testedIP.Contains(test.stringIP)
			if test.res != r {
				t.Errorf("Contains() = %v, want %v", r, test.res)
			}
		})
	}
}

func helpParseNetIPs(t *testing.T, ips []string) ipchecking.NetIPs {
	t.Helper()

	nip, err := ipchecking.ParseNetIPs(ips)
	if err != nil {
		t.Errorf("Error in IP building: %q, with err %v", nip, err)
	}

	return nip
}

func TestNetIPsContains(t *testing.T) {
	t.Parallel()

	ips := helpParseNetIPs(t, []string{
		"127.0.0.1",
		"10.0.0.0/24",
		"::1",
		"2001:db8::/32",
	})

	tests := []struct {
		name     string
		stringIP string
		testedIP ipchecking.NetIP
		res      bool
	}{
		{
			name:     "IPv4 match",
			stringIP: "127.0.0.1",
			res:      true,
		},
		{
			name:     "IPv4 match CIDR",
			stringIP: "10.0.0.1",
			res:      true,
		},
		{
			name:     "IPv4 No Match",
			stringIP: "11.0.0.1",
			res:      false,
		},
		{
			name:     "IPv6 match",
			stringIP: "::1",
			res:      true,
		},
		{
			name:     "IPv6 match CIDR",
			stringIP: "2001:db8:beba:cafe::1:2",
			res:      true,
		},
		{
			name:     "IPv6 No Match",
			stringIP: "ff0X::101",
			res:      false,
		},
		{
			name:     "invalid IPv4",
			stringIP: "127.0.0.1.42",
			res:      false,
		},
		{
			name:     "invalid IPv6",
			stringIP: "::1::",
			res:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := ips.Contains(test.stringIP)
			if test.res != r {
				t.Errorf("Contains() = %v, want %v", r, test.res)
			}
		})
	}
}

func TestNetIPString(t *testing.T) {
	t.Parallel()

	ipv4 := helpParseNetIP(t, "127.0.0.1/32")
	ipv6 := helpParseNetIP(t, "::1/128")

	tests := []struct {
		name          string
		testedIP      string
		stringIP      ipchecking.NetIP
		expectIsEqual bool
	}{
		{
			name:          "Valid IPv4 string",
			testedIP:      "127.0.0.1/32",
			stringIP:      ipv4,
			expectIsEqual: true,
		},
		{
			name:          "Invalid IPv4 string",
			testedIP:      "127.0.0.2/32",
			stringIP:      ipv4,
			expectIsEqual: false,
		},
		{
			name:          "Valid IPv6 string",
			testedIP:      "::1/128",
			stringIP:      ipv6,
			expectIsEqual: true,
		},
		{
			name:          "Invalid IPv6 string",
			testedIP:      "::2/128",
			stringIP:      ipv6,
			expectIsEqual: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := test.stringIP.String()
			if test.expectIsEqual {
				if r != test.testedIP {
					t.Errorf("String() = %q, want %q", r, test.testedIP)
				}
			} else {
				if r == test.testedIP {
					t.Errorf("String() = %q, want not %q", r, test.testedIP)
				}
			}
		})
	}
}
