// Package ipchecking wrapper over net/netip to compare both IP and CIRD.
package ipchecking

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"
)

// IPViewed struct.
type IPViewed struct {
	Viewed time.Time
	Count  int
	Denied bool
}

// NetIP struct that holds an NetIP IP address, and a IP network.
// If the network is nil, the NetIP is a single IP.
type NetIP struct {
	Net  *netip.Prefix
	Addr netip.Addr
}

// ParseNetIPs Parse a slice string to extract the netip.
// Returns an error on the first IP that failed to parse.
func ParseNetIPs(iplist []string) (NetIPs, error) {
	rlist := make([]NetIP, 0, len(iplist))

	for _, v := range iplist {
		ip, err := ParseNetIP(v)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q: %w", v, err)
		}

		rlist = append(rlist, ip)
	}

	return rlist, nil
}

// ParseNetIP Parse a string to extract the netip.
func ParseNetIP(ip string) (NetIP, error) {
	tmpSubnet := strings.Split(ip, "/")
	if len(tmpSubnet) == 1 {
		tempIP, err := netip.ParseAddr(ip)
		if err != nil {
			return NetIP{}, fmt.Errorf("failed to parse %q: %s", ip, err.Error())
		}

		return NetIP{Addr: tempIP}, nil
	}

	ipNet, err := netip.ParsePrefix(ip)
	if err != nil {
		return NetIP{}, fmt.Errorf("failed to parse CIDR %q: %w", ip, err)
	}

	return NetIP{Net: &ipNet}, nil
}

// String convert IP struct to string.
func (ip NetIP) String() string {
	if ip.Net == nil {
		return ip.Addr.String()
	}

	return ip.Net.String()
}

// Contains Check is the IP is the same or in the same subnet.
func (ip NetIP) Contains(i string) bool {
	rip, err := netip.ParseAddr(i)
	if err != nil {
		log.Printf("%s is not a valid IP or IP/Net: %s", i, err.Error())

		return false
	}

	if ip.Net == nil {
		return ip.Addr == rip
	}

	return ip.Net.Contains(rip)
}

type NetIPs []NetIP

// Contains Check is the IP is the same or in the same subnet.
func (netIPs NetIPs) Contains(ip string) bool {
	rip, err := netip.ParseAddr(ip)
	if err != nil {
		log.Printf("failed to parse %q: %s", ip, err.Error())

		return false
	}

	for _, netIP := range netIPs {
		if netIP.Net == nil {
			if netIP.Addr == rip {
				return true
			}

			continue
		}

		if netIP.Net.Contains(rip) {
			return true
		}
	}

	return false
}
