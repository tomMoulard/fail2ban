package ipchecking

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

var (
	// Logger ip checking logger
	Logger = log.New(os.Stdout, "IPChecking: ", log.Ldate|log.Ltime|log.Lshortfile)
)

// IP struct that holds an IP Addr
type IP struct {
	Net *net.IPNet
}

// StrToIP convert ip string array to ip struct array
func StrToIP(iplist []string) ([]IP, error) {
	rlist := []IP{}
	for _, v := range iplist {
		ip, err := BuildIP(v)
		if err != nil {
			Logger.Printf("Error: %s not valid", v)

			continue
		}
		rlist = append(rlist, ip)
	}

	return rlist, nil
}

func isIPv4(ip string) bool {
	return strings.Contains(ip, ".")
}

// BuildIP Parse a string to extract the IP
func BuildIP(ip string) (IP, error) {
	var res IP
	var err error

	tmpSubnet := strings.Split(ip, "/")
	if len(tmpSubnet) == 1 {
		tempIP := net.ParseIP(ip)
		if tempIP == nil {
			Logger.Printf("%s is not a valid IP or IP/Net", ip)

			return res, fmt.Errorf("%s is not a valid IP or IP/Net", ip)
		}
		if isIPv4(ip) {
			ip = ip + "/32"
		} else {
			ip = ip + "/128"
		}
	}
	_, ipNet, err := net.ParseCIDR(ip)
	if err != nil {
		Logger.Printf("%e", err)

		return res, fmt.Errorf("failed to parse CIDR: %w", err)
	}
	res.Net = ipNet

	return res, nil
}

// ToString convert IP struct to string
func (ip IP) ToString() string {
	return ip.Net.String()
}

// CheckIPInSubnet Check is the IP Is the same or in the same subnet
func (ip IP) CheckIPInSubnet(i string) bool {
	return ip.Net.Contains(net.ParseIP(i))
}
