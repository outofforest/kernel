package main

import (
	"github.com/outofforest/cloudless/pkg/acpi"
	. "github.com/outofforest/cloudless/pkg/config" //nolint:stylecheck
	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/ntp"
	"github.com/outofforest/cloudless/pkg/pxe"
	"github.com/outofforest/cloudless/pkg/ssh"
	"github.com/outofforest/cloudless/pkg/virt"
	"github.com/outofforest/cloudless/pkg/yum"
)

var cfg = func() host.Config {
	var cfg host.Config
	cfg = host.Config{
		KernelModules: KernelModules,
		DNS:           DNS,
		Services: []host.Service{
			acpi.NewPowerService(),
			ntp.NewService(),
			ssh.NewService("AAAAC3NzaC1lZDI1NTE5AAAAIEcJvvtOBgTsm3mq3Sg8cjn6Mz/vC9f3k6a89ZOjIyF6"),
		},
		Hosts: map[string]host.Host{
			"demo": {
				Gateway: IP4("10.0.0.1"),
				Networks: []host.Network{
					Network("00:01:0a:00:00:9b", "10.0.0.155/24"),
				},
				Services: []host.Service{
					virt.NewService(
						virt.NATedNetwork(),
						virt.VM(),
					),
				},
			},
			"vm": {
				Gateway: IP4("10.0.1.1"),
				Networks: []host.Network{
					Network("00:01:0a:00:02:05", "10.0.1.2/24"),
				},
			},
			"pxe": {
				Gateway: IP4("10.0.0.1"),
				Networks: []host.Network{
					Network("00:01:0a:00:00:05", "10.0.0.100/24", "fe80::cba:4be3:12c0:7475/64",
						"fd27:cd4c:c349::1/64"),
				},
				Services: []host.Service{
					pxe.NewService("/dev/sda"),
					yum.NewService("/tmp/repo", host.PackageListProvider(&cfg)),
				},
			},
		},
	}

	return cfg
}()
