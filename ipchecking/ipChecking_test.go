package ipchecking_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/ipchecking"
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
		res      assert.ErrorAssertionFunc
	}{
		{
			name:     "Valid IPv4",
			stringIP: "127.0.0.1",
			res:      assert.NoError,
		},
		{
			name:     "Invalid IPv4 value 8 first bits",
			stringIP: "25666.0.0.1",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv4 value 8 second bits",
			stringIP: "127.4444.0.1",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv4 value 8 third bits",
			stringIP: "127.0.4440.1",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv4 value 8 last bits",
			stringIP: "127.0.0.1233",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv4 CIDR form",
			stringIP: "127.0.0.1/22/34",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv4 CIDR ",
			stringIP: "127.0.0.1/55",
			res:      assert.Error,
		},
		{
			name:     "Missing IPv4 CIDR ",
			stringIP: "127.0.0.1/",
			res:      assert.Error,
		},
		{
			name:     "Valid IPv4 CIDR ",
			stringIP: "127.0.0.1/23",
			res:      assert.NoError,
		},
		{
			name:     "Valid IPv6",
			stringIP: "::1",
			res:      assert.NoError,
		},
		{
			name:     "Invalid IPv6 value 8 first bits",
			stringIP: "2566634::1",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv6 value 8 second bits",
			stringIP: "127:444234564:0::1",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv6 value 8 third bits",
			stringIP: "1::4440345::1",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv6 value 8 last bits",
			stringIP: "::34561233",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv6 CIDR form",
			stringIP: "::1/22/34",
			res:      assert.Error,
		},
		{
			name:     "Invalid IPv6 CIDR ",
			stringIP: "::1/234",
			res:      assert.Error,
		},
		{
			name:     "Missing IPv6 CIDR ",
			stringIP: "::1/",
			res:      assert.Error,
		},
		{
			name:     "Valid IPv6 CIDR ",
			stringIP: "::1/53",
			res:      assert.NoError,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := ipchecking.ParseNetIP(tt.stringIP)
			tt.res(t, err)
		})
	}
}

func TestNetIPParseNetIPs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		ips         []string
		expectedIPs []string
		expectErr   assert.ErrorAssertionFunc
	}{
		{
			name:        "valid IPv4",
			ips:         []string{"127.0.0.1", "127.0.0.2"},
			expectedIPs: []string{"127.0.0.1", "127.0.0.2"},
			expectErr:   assert.NoError,
		},
		{
			name:        "valid IPv6",
			ips:         []string{"::1", "::2"},
			expectedIPs: []string{"::1", "::2"},
			expectErr:   assert.NoError,
		},
		{
			name:      "invalid IPv4",
			ips:       []string{"127.0.0.1.1", "127.0.0.2.42"},
			expectErr: assert.Error,
		},
		{
			name:      "invalid IPv6",
			ips:       []string{"::1", "::2::42:"},
			expectErr: assert.Error,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ipchecking.ParseNetIPs(tt.ips)
			tt.expectErr(t, err)

			for i, gotIP := range got {
				assert.Equal(t, tt.expectedIPs[i], gotIP.String())
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

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := tt.testedIP.Contains(tt.stringIP)
			assert.Equal(t, tt.res, r)
		})
	}
}

func helpParseNetIPs(t *testing.T, ips []string) ipchecking.NetIPs {
	t.Helper()

	nip, err := ipchecking.ParseNetIPs(ips)
	require.NoError(t, err)

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

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := ips.Contains(tt.stringIP)
			assert.Equal(t, tt.res, r)
		})
	}
}

func TestNetIPString(t *testing.T) {
	t.Parallel()

	ipv4 := helpParseNetIP(t, "127.0.0.1/32")
	ipv6 := helpParseNetIP(t, "::1/128")

	tests := []struct {
		name     string
		testedIP string
		stringIP ipchecking.NetIP
		res      assert.ComparisonAssertionFunc
	}{
		{
			name:     "Valid IPv4 string",
			testedIP: "127.0.0.1/32",
			stringIP: ipv4,
			res:      assert.Equal,
		},
		{
			name:     "Invalid IPv4 string",
			testedIP: "127.0.0.2/32",
			stringIP: ipv4,
			res:      assert.NotEqual,
		},
		{
			name:     "Valid IPv6 string",
			testedIP: "::1/128",
			stringIP: ipv6,
			res:      assert.Equal,
		},
		{
			name:     "Invalid IPv6 string",
			testedIP: "::2/128",
			stringIP: ipv6,
			res:      assert.NotEqual,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r := tt.stringIP.String()
			tt.res(t, tt.testedIP, r)
		})
	}
}
