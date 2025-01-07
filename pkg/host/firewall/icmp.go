package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// AllowICMPv4 allows for ICMPv4 traffic.
func AllowICMPv4() RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.FilterInput,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_ICMP},
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
		}
	}
}

// AllowICMPv6 allows for ICMPv6 traffic.
func AllowICMPv6() RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.FilterInput,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_ICMPV6},
					},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
		}
	}
}
