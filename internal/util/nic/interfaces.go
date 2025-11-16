package nic

import (
	"strings"

	"github.com/vishvananda/netlink"
)

type LinkType = string

const (
	DeviceType LinkType = "device"
	NetKitType LinkType = "netkit"
	VethType   LinkType = "veth"
)

type InterfaceInfo struct {
	Name  string
	Index int
}

type Filter struct {
	IncludeIfaces   []string
	IncludePrefixes []string
	ExcludeIfaces   []string
	ExcludePrefixes []string
	LinkType        LinkType
}

// ListFilteredInterface returns a list of interfaces that match given filter.
func ListFilteredInterface(filter *Filter) ([]InterfaceInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	var infos []InterfaceInfo

	for _, link := range links {
		ifName := link.Attrs().Name
		linkType := link.Type()

		// 1. link type filter
		if filter.LinkType != linkType {
			continue
		}

		if matchExclude(ifName, filter.ExcludeIfaces, filter.ExcludePrefixes) {
			continue
		}

		if !matchInclude(ifName, filter.IncludeIfaces, filter.IncludePrefixes) {
			continue
		}

		info := InterfaceInfo{
			Name:  ifName,
			Index: link.Attrs().Index,
		}

		infos = append(infos, info)
	}

	return infos, nil
}

// matchInclude determines whether an interface name should be included.
// Logic:
//  1. If both includeIfaces and includePrefixes are empty → allow everything (no restrictions).
//  2. If includeIfaces contains an exact match → allow.
//  3. If includePrefixes contains a matching prefix → allow.
//  4. Otherwise → reject.
func matchInclude(name string, includeIfaces, includePrefixes []string) bool {
	// 1. No include rules → allow all
	if len(includeIfaces) == 0 && len(includePrefixes) == 0 {
		return true
	}

	// 2. Exact match
	for _, ifname := range includeIfaces {
		if name == ifname {
			return true
		}
	}

	// 3. Prefix match
	for _, prefix := range includePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}

	// 4. Not matching any include rule
	return false
}

// matchExclude determines whether an interface name should be excluded.
// Logic:
//   - If the interface name matches any prefix in excludePrefixes → exclude.
//   - Otherwise allow.
func matchExclude(name string, excludeIfaces, excludePrefixes []string) bool {
	for _, p := range excludePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
