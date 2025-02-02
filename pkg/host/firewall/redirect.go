package firewall

import (
	"github.com/google/nftables"

	"github.com/outofforest/cloudless/pkg/host/firewall/rules"
	"github.com/outofforest/cloudless/pkg/parse"
)

// RedirectV4TCPPort redirects TCPv4 port.
func RedirectV4TCPPort(externalIP string, externalPort uint16, internalIP string, internalPort uint16) RuleSource {
	externalIPParsed := parse.IP4(externalIP)
	internalIPParsed := parse.IP4(internalIP)
	return func(chains Chains) ([]*nftables.Rule, error) {
		return []*nftables.Rule{
			{
				Chain: chains.V4NATPrerouting,
				Exprs: rules.Expressions(
					rules.Protocol("tcp"),
					rules.LocalDestinationAddress(),
					rules.DestinationAddress(externalIPParsed),
					rules.DestinationPort(externalPort),
					rules.DestinationNAT(internalIPParsed, internalPort),
				),
			},
		}, nil
	}
}

// RedirectV4UDPPort redirects UDPv4 port.
func RedirectV4UDPPort(externalIP string, externalPort uint16, internalIP string, internalPort uint16) RuleSource {
	externalIPParsed := parse.IP4(externalIP)
	internalIPParsed := parse.IP4(internalIP)
	return func(chains Chains) ([]*nftables.Rule, error) {
		return []*nftables.Rule{
			{
				Chain: chains.V4NATPrerouting,
				Exprs: rules.Expressions(
					rules.Protocol("udp"),
					rules.LocalDestinationAddress(),
					rules.DestinationAddress(externalIPParsed),
					rules.DestinationPort(externalPort),
					rules.DestinationNAT(internalIPParsed, internalPort),
				),
			},
		}, nil
	}
}
