package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"

	"github.com/outofforest/cloudless/pkg/kernel"
	"github.com/outofforest/cloudless/pkg/mount"
	"github.com/outofforest/cloudless/pkg/system"
	"github.com/outofforest/logger"
	"github.com/outofforest/run"
)

func main() {
	run.New().Run(context.Background(), "init", func(ctx context.Context) (retErr error) {
		defer func() {
			if retErr != nil {
				logger.Get(ctx).Error("Error", zap.Error(retErr))
				time.Sleep(30 * time.Second)
			}
		}()

		fmt.Println("I am outofforest init process!")

		if err := mount.ProcFS("/proc"); err != nil {
			return err
		}

		if err := kernel.LoadModule("virtio_net"); err != nil {
			return err
		}

		links, err := netlink.LinkList()
		if err != nil {
			return errors.WithStack(err)
		}

		for _, l := range links {
			if l.Attrs().Name == "lo" {
				continue
			}

			if err := netlink.AddrAdd(l, &netlink.Addr{
				IPNet: &net.IPNet{
					IP:   net.IPv4(10, 0, 0, 155),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			}); err != nil {
				return errors.WithStack(err)
			}
			if err := netlink.LinkSetUp(l); err != nil {
				return errors.WithStack(err)
			}
			if err := netlink.RouteAdd(&netlink.Route{
				Scope:     netlink.SCOPE_UNIVERSE,
				LinkIndex: l.Attrs().Index,
				Gw:        net.IPv4(10, 0, 0, 1),
			}); err != nil {
				return errors.WithStack(err)
			}

			break
		}

		if err := mount.Root(); err != nil {
			return err
		}

		return system.StartSystemD()
	})
}
