package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// OpenV4TCPPort allows IPv4 TCP connections to the port.
func OpenV4TCPPort(port uint16) RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.V4FilterInput,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(port),
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
		}
	}
}

// OpenV4UDPPort allows IPv4 UDP connections to the port.
func OpenV4UDPPort(port uint16) RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.V4FilterInput,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_UDP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(port),
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
		}
	}
}

// OpenV6TCPPort allows IPv6 TCP connections to the port.
func OpenV6TCPPort(port uint16) RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.V6FilterInput,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(port),
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
		}
	}
}

// OpenV6UDPPort allows IPv6 UDP connections to the port.
func OpenV6UDPPort(port uint16) RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.V6FilterInput,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_UDP},
					},
					&expr.Payload{
						DestRegister: 1,
						Base:         expr.PayloadBaseTransportHeader,
						Offset:       2,
						Len:          2,
					},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     binaryutil.BigEndian.PutUint16(port),
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
		}
	}
}
