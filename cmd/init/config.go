package main

import (
	"net"

	"github.com/outofforest/cloudless/pkg/acpi"
	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/ntp"
	"github.com/outofforest/cloudless/pkg/pxe"
	"github.com/outofforest/cloudless/pkg/ssh"
)

var config = []host.Config{
	{
		Hostname: "demo",
		Networks: []host.Network{
			{
				MAC: net.HardwareAddr{0x00, 0x01, 0x0a, 0x00, 0x00, 0x9b},
				IPs: []net.IPNet{
					{
						IP:   net.IPv4(10, 0, 0, 155),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
				Gateway: net.IPv4(10, 0, 0, 1),
			},
		},
		DNS: []net.IP{
			net.IPv4(1, 1, 1, 1),
			net.IPv4(8, 8, 8, 8),
		},
	},
	{
		Hostname:      "pxe",
		KernelModules: []string{"virtio_scsi"},
		Networks: []host.Network{
			{
				MAC: net.HardwareAddr{0x00, 0x01, 0x0a, 0x00, 0x00, 0x05},
				IPs: []net.IPNet{
					{
						IP:   net.IPv4(10, 0, 0, 100),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
					{
						IP:   net.ParseIP("fe80::cba:4be3:12c0:7475"),
						Mask: net.CIDRMask(64, 128),
					},
					{
						IP:   net.ParseIP("fd27:cd4c:c349::1"),
						Mask: net.CIDRMask(64, 128),
					},
				},
				Gateway: net.IPv4(10, 0, 0, 1),
			},
		},
		DNS: []net.IP{
			net.IPv4(1, 1, 1, 1),
			net.IPv4(8, 8, 8, 8),
		},
		Services: []host.Service{
			acpi.NewPowerService(),
			ntp.NewService(),
			ssh.NewService("AAAAC3NzaC1lZDI1NTE5AAAAIEcJvvtOBgTsm3mq3Sg8cjn6Mz/vC9f3k6a89ZOjIyF6"),
			pxe.NewService("/dev/sda"),
		},
	},
}
