package firewall

import (
	"github.com/google/nftables"

	"github.com/outofforest/cloudless/pkg/host/firewall/rules"
	"github.com/outofforest/cloudless/pkg/parse"
)

// RedirectV4TCPPort redirects TCPv4 port.
func RedirectV4TCPPort(externalIP string, externalPort uint16, internalIPNet string, internalPort uint16) RuleSource {
	externalIPParsed := parse.IP4(externalIP)
	internalIPNetParsed := parse.IPNet4(internalIPNet)
	return func(chains Chains) ([]*nftables.Rule, error) {
		return []*nftables.Rule{
			// Redirecting requests from the host machine.
			{
				Chain: chains.V4NATOutput,
				Exprs: rules.Expressions(
					rules.Protocol("tcp"),
					rules.DestinationAddress(externalIPParsed),
					rules.DestinationPort(externalPort),
					rules.DestinationNAT(internalIPNetParsed.IP, internalPort),
				),
			},

			// Redirecting requests from other hosts in the internal network.
			{
				Chain: chains.V4NATPostrouting,
				Exprs: rules.Expressions(
					rules.Protocol("tcp"),
					rules.SourceNetwork(&internalIPNetParsed),
					rules.DestinationAddress(internalIPNetParsed.IP),
					rules.DestinationPort(internalPort),
					rules.Masquerade(),
				),
			},

			// Redirecting external requests.
			{
				Chain: chains.V4NATPrerouting,
				Exprs: rules.Expressions(
					rules.Protocol("tcp"),
					rules.DestinationAddress(externalIPParsed),
					rules.DestinationPort(externalPort),
					rules.DestinationNAT(internalIPNetParsed.IP, internalPort),
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
