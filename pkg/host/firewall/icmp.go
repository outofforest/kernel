package firewall

import (
	"github.com/google/nftables"

	"github.com/outofforest/cloudless/pkg/host/firewall/rules"
)

// AllowICMPv4 allows for ICMPv4 traffic.
func AllowICMPv4() RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.V4FilterInput,
				Exprs: rules.Expressions(
					rules.Protocol("icmpv4"),
					rules.Accept(),
				),
			},
		}
	}
}

// AllowICMPv6 allows for ICMPv6 traffic.
func AllowICMPv6() RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.V6FilterInput,
				Exprs: rules.Expressions(
					rules.Protocol("icmpv6"),
					rules.Accept(),
				),
			},
		}
	}
}
