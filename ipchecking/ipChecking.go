package ipchecking

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

var (
	// Logger ip checking logger
	Logger = log.New(os.Stdout, "IPChecking: ", log.Ldate|log.Ltime|log.Lshortfile)
)

// IP struct that holds an IP Addr
type IP struct {
	IP   uint32
	Cidr uint32
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

// BuildIP Parse a string to extract the IP
func BuildIP(ip string) (IP, error) {
	var res IP
	var tmpInt uint64
	var err error

	tmpSubnet := strings.Split(ip, "/")
	tmpIP := strings.Split(tmpSubnet[0], ".")

	if len(tmpSubnet) <= 2 && len(tmpIP) == 4 {
		if tmpInt, err = strconv.ParseUint(tmpIP[0], 10, 32); err == nil && tmpInt <= 255 {
			res.IP = uint32(tmpInt) << 24
		}
		if tmpInt, err = strconv.ParseUint(tmpIP[1], 10, 32); err == nil && tmpInt <= 255 {
			res.IP += uint32(tmpInt) << 16
		}
		if tmpInt, err = strconv.ParseUint(tmpIP[2], 10, 32); err == nil && tmpInt <= 255 {
			res.IP += uint32(tmpInt) << 8
		}
		if tmpInt, err = strconv.ParseUint(tmpIP[3], 10, 32); err == nil && tmpInt <= 255 {
			res.IP += uint32(tmpInt)
		}
		if len(tmpSubnet) == 2 {
			if tmpInt, err = strconv.ParseUint(tmpSubnet[1], 10, 32); err == nil && tmpInt <= 255 {
				res.Cidr = 0xFFFFFFFF << uint32(tmpInt)
			}
		} else {
			res.Cidr = 0xFFFFFFFF
		}
	} else {
		err = fmt.Errorf("The string is not an IP not a Subnet")
		return IP{}, err
	}
	return res, nil
}

// CheckIPInSubnet Check is the IP Is the same or in the same subnet
func (i IP) CheckIPInSubnet(ip string) bool {
	checkIP, err := BuildIP(ip)
	if err != nil {
		return false
	}
	return i.IP&i.Cidr == checkIP.IP&i.Cidr
}
