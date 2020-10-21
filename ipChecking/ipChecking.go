package ipChecking

import (
	"fmt"
	"strconv"
	"strings"
)

type Ip struct {
	Ip   uint32
	Cidr uint32
}

func BuildIp(ip string) (Ip, error) {
	var res Ip
	var tmpInt uint64
	var err error

	tmpSubnet := strings.Split(ip, "/")
	tmpIp := strings.Split(tmpSubnet[0], ".")

	if len(tmpSubnet) <= 2 && len(tmpIp) == 4 {
		if tmpInt, err = strconv.ParseUint(tmpIp[0], 10, 32); err == nil && tmpInt <= 255 {
			res.Ip = uint32(tmpInt) << 24
		}
		if tmpInt, err = strconv.ParseUint(tmpIp[1], 10, 32); err == nil && tmpInt <= 255 {
			res.Ip += uint32(tmpInt) << 16
		}
		if tmpInt, err = strconv.ParseUint(tmpIp[2], 10, 32); err == nil && tmpInt <= 255 {
			res.Ip += uint32(tmpInt) << 8
		}
		if tmpInt, err = strconv.ParseUint(tmpIp[3], 10, 32); err == nil && tmpInt <= 255 {
			res.Ip += uint32(tmpInt)
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
		return Ip{}, err
	}
	return res, nil
}

func (i Ip) CheckIpInSubnet(ip string) bool {
	checkIp, err := BuildIp(ip)
	if err != nil {
		return false
	}
	fmt.Println(i.Cidr)
	fmt.Println(i.Ip)
	fmt.Println(checkIp.Ip)

	return i.Ip&i.Cidr == checkIp.Ip&i.Cidr
}
