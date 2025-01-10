package host

import (
	"net"
	"syscall"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// DefaultIface returns name of the interface configured as default gateway.
func DefaultIface() (string, error) {
	routes, err := netlink.RouteList(nil, syscall.AF_UNSPEC)
	if err != nil {
		return "", errors.WithStack(err)
	}

	for _, r := range routes {
		if isDefaultRoute(r) {
			defaultIface, err := net.InterfaceByIndex(r.LinkIndex)
			if err != nil {
				return "", errors.WithStack(err)
			}
			return defaultIface.Name, nil
		}
	}
	return "", errors.New("default network interface not found")
}

func isDefaultRoute(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	ones, _ := route.Dst.Mask.Size()
	return ones == 0
}
