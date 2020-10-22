package ipchecking

import (
	"fmt"
	"strconv"
	"strings"
)

// IP struct that holds an IP Addr
type IP struct {
	IP     uint32
	Cidr   uint32
	String string
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
	res.String = ip
	return res, nil
}

func (ip IP) ToString() string {
	return ip.String
}

// CheckIPInSubnet Check is the IP Is the same or in the same subnet
func (i IP) CheckIPInSubnet(ip string) bool {
	checkIP, err := BuildIP(ip)
	if err != nil {
		return false
	}
	return i.IP&i.Cidr == checkIP.IP&i.Cidr
}
