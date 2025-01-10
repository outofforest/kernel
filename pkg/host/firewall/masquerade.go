package firewall

import (
	"github.com/google/nftables"

	"github.com/outofforest/cloudless/pkg/host/firewall/rules"
)

// Masquerade masquerades traffic.
func Masquerade(internalInterface, externalInterface string) RuleSource {
	return func(chains Chains) []*nftables.Rule {
		return []*nftables.Rule{
			{
				Chain: chains.V4NATPostrouting,
				Exprs: rules.Expressions(
					rules.IncomingInterface(internalInterface),
					rules.OutgoingInterface(externalInterface),
					rules.Masquerade(),
				),
			},
		}
	}
}
