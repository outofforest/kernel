package dhcp6

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/net/ipv6"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const dhcp6ServerPort = 547

// Run runs DHCP IPv6 server giving random IP addresses required to send EFI payload later.
func Run(ctx context.Context) error {
	conn, err := newUDPConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		return errors.WithStack(err)
	}

	p := ipv6.NewPacketConn(conn)
	if err := p.JoinGroup(iface, &net.UDPAddr{
		IP:   net.ParseIP("ff02::1:2"),
		Port: dhcp6ServerPort,
	}); err != nil {
		return errors.WithStack(err)
	}

	b := make([]byte, 4096)

	fmt.Println("==== Reading")
	n, addr, err := conn.ReadFrom(b)
	if err != nil {
		return errors.WithStack(err)
	}

	fmt.Println(addr.String())
	fmt.Printf("%#v\n", b[:n])

	return errors.New("test")
}

func newUDPConnection() (*net.UDPConn, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	f := os.NewFile(uintptr(fd), "")
	defer f.Close()

	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 1); err != nil {
		return nil, errors.WithStack(err)
	}

	if err := unix.Bind(fd, &unix.SockaddrInet6{Port: dhcp6ServerPort}); err != nil {
		return nil, errors.WithStack(err)
	}

	conn, err := net.FilePacketConn(f)
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
