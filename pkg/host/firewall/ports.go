package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// OpenTCPPort allows for TCP connections to the port.
func OpenTCPPort(port uint16) RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.FilterInput,
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

// OpenUDPPort allows UDP connections to the port.
func OpenUDPPort(port uint16) RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.FilterInput,
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
