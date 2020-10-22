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
	IP     uint32
	Cidr   uint32
	String string
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
		for i := 24; i >= 0; i -= 8 {
			if tmpInt, err = strconv.ParseUint(tmpIP[3-i/8], 10, 32); err == nil && tmpInt <= 255 {
				res.IP += (uint32(tmpInt) << i)
			} else {
				if tmpInt > 255 {
					err = fmt.Errorf("Invalid IP field: %d", tmpInt)
				}
				return IP{}, err
			}
		}
		if len(tmpSubnet) == 2 {
			if tmpInt, err = strconv.ParseUint(tmpSubnet[1], 10, 32); err == nil && tmpInt <= 32 {
				res.Cidr = uint32(tmpInt)
			} else {
				if tmpInt > 32 {
					return IP{}, fmt.Errorf("Invalid CIDR value: %d", tmpInt)
				}

				return IP{}, err
			}
		} else {
			res.Cidr = 32
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
	return i.IP>>(32-i.Cidr) == checkIP.IP>>(32-i.Cidr)
}
