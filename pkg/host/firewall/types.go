package firewall

import (
	"github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/samber/lo"

	"github.com/outofforest/cloudless/pkg/host/firewall/rules"
)

const (
	tableName               = "cloudless"
	filterInputChainName    = "filter_input"
	filterOutputChainName   = "filter_output"
	filterForwardChainName  = "filter_forward"
	natPostroutingChainName = "nat_postrouting"
)

// EnsureChains ensures the firewall foundation.
func EnsureChains() (Chains, error) {
	c := &nftables.Conn{}

	nfTableV6 := c.AddTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyIPv6,
	})
	nfTableV4 := c.AddTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyIPv4,
	})
	filterInputChainV6 := c.AddChain(&nftables.Chain{
		Name:     filterInputChainName,
		Table:    nfTableV6,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	})
	filterInputChainV4 := c.AddChain(&nftables.Chain{
		Name:     filterInputChainName,
		Table:    nfTableV4,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	})
	c.AddChain(&nftables.Chain{
		Name:     filterOutputChainName,
		Table:    nfTableV6,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyAccept),
	})
	c.AddChain(&nftables.Chain{
		Name:     filterOutputChainName,
		Table:    nfTableV4,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyAccept),
	})
	c.AddChain(&nftables.Chain{
		Name:     filterForwardChainName,
		Table:    nfTableV6,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	})
	filterForwardChainV4 := c.AddChain(&nftables.Chain{
		Name:     filterForwardChainName,
		Table:    nfTableV4,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	})
	natPostroutingChainV4 := c.AddChain(&nftables.Chain{
		Name:     natPostroutingChainName,
		Table:    nfTableV4,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Policy:   lo.ToPtr(nftables.ChainPolicyAccept),
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV6,
		Chain: filterInputChainV6,
		Exprs: rules.Expressions(
			rules.Protocol("icmpv6"),
			rules.Accept(),
		),
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV4,
		Chain: filterInputChainV4,
		Exprs: rules.Expressions(
			rules.Protocol("icmpv4"),
			rules.Accept(),
		),
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV6,
		Chain: filterInputChainV6,
		Exprs: rules.Expressions(
			rules.ConnectionEstablished(),
			rules.Accept(),
		),
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV4,
		Chain: filterInputChainV4,
		Exprs: rules.Expressions(
			rules.ConnectionEstablished(),
			rules.Accept(),
		),
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV4,
		Chain: filterInputChainV4,
		Exprs: rules.Expressions(
			rules.IncomingInterface("lo"),
			rules.LocalSourceAddress(),
			rules.Accept(),
		),
	})

	if err := c.Flush(); err != nil {
		return Chains{}, errors.WithStack(err)
	}
	return Chains{
		V4FilterInput:    filterInputChainV4,
		V4FilterForward:  filterForwardChainV4,
		V4NATPostrouting: natPostroutingChainV4,
		V6FilterInput:    filterInputChainV6,
	}, nil
}

// Chains is the list of chains to be used for rules.
type Chains struct {
	V4FilterInput    *nftables.Chain
	V4FilterForward  *nftables.Chain
	V4NATPostrouting *nftables.Chain
	V6FilterInput    *nftables.Chain
}

// RuleSource generates firewall rules.
type RuleSource func(chains Chains) []*nftables.Rule
