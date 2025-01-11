package firewall

import (
	"github.com/google/nftables"

	"github.com/outofforest/cloudless/pkg/host/firewall/rules"
)

// OpenV4TCPPort allows IPv4 TCP connections to the port.
func OpenV4TCPPort(port uint16) RuleSource {
	return func(chains Chains) ([]*nftables.Rule, error) {
		return []*nftables.Rule{
			{
				Chain: chains.V4FilterInput,
				Exprs: rules.Expressions(
					rules.Protocol("tcp"),
					rules.DestinationPort(port),
					rules.Accept(),
				),
			},
		}, nil
	}
}

// OpenV4UDPPort allows IPv4 UDP connections to the port.
func OpenV4UDPPort(port uint16) RuleSource {
	return func(chains Chains) ([]*nftables.Rule, error) {
		return []*nftables.Rule{
			{
				Chain: chains.V4FilterInput,
				Exprs: rules.Expressions(
					rules.Protocol("udp"),
					rules.DestinationPort(port),
					rules.Accept(),
				),
			},
		}, nil
	}
}

// OpenV6TCPPort allows IPv6 TCP connections to the port.
func OpenV6TCPPort(port uint16) RuleSource {
	return func(chains Chains) ([]*nftables.Rule, error) {
		return []*nftables.Rule{
			{
				Chain: chains.V6FilterInput,
				Exprs: rules.Expressions(
					rules.Protocol("tcp"),
					rules.DestinationPort(port),
					rules.Accept(),
				),
			},
		}, nil
	}
}

// OpenV6UDPPort allows IPv6 UDP connections to the port.
func OpenV6UDPPort(port uint16) RuleSource {
	return func(chains Chains) ([]*nftables.Rule, error) {
		return []*nftables.Rule{
			{
				Chain: chains.V6FilterInput,
				Exprs: rules.Expressions(
					rules.Protocol("udp"),
					rules.DestinationPort(port),
					rules.Accept(),
				),
			},
		}, nil
	}
}
