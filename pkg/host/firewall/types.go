package firewall

import (
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/samber/lo"
)

const (
	tableName              = "cloudless"
	filterInputChainName   = "filter_input"
	filterOutputChainName  = "filter_output"
	filterForwardChainName = "filter_forward"
)

// EnsureChains ensures the firewall foundation.
func EnsureChains(c *nftables.Conn) Chains {
	nfTableV6 := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyIPv6,
	}
	c.AddTable(nfTableV6)

	nfTableV4 := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyIPv4,
	}
	c.AddTable(nfTableV4)

	filterInputChainV6 := c.AddChain(&nftables.Chain{
		Name:     filterInputChainName,
		Table:    nfTableV6,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	})
	c.AddChain(filterInputChainV6)

	filterInputChainV4 := c.AddChain(&nftables.Chain{
		Name:     filterInputChainName,
		Table:    nfTableV4,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	})
	c.AddChain(filterInputChainV4)

	c.AddRule(&nftables.Rule{
		Table: nfTableV6,
		Chain: filterInputChainV6,
		Exprs: []expr.Any{
			&expr.Ct{
				Register:       1,
				SourceRegister: false,
				Key:            expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0, 0, 0, 0},
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV4,
		Chain: filterInputChainV4,
		Exprs: []expr.Any{
			&expr.Ct{
				Register:       1,
				SourceRegister: false,
				Key:            expr.CtKeySTATE,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0, 0, 0, 0},
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV6,
		Chain: filterInputChainV6,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("lo\x00"),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.AddRule(&nftables.Rule{
		Table: nfTableV4,
		Chain: filterInputChainV4,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte("lo\x00"),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})

	c.AddChain(c.AddChain(&nftables.Chain{
		Name:     filterOutputChainName,
		Table:    nfTableV6,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyAccept),
	}))

	c.AddChain(c.AddChain(&nftables.Chain{
		Name:     filterOutputChainName,
		Table:    nfTableV4,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyAccept),
	}))

	c.AddChain(c.AddChain(&nftables.Chain{
		Name:     filterForwardChainName,
		Table:    nfTableV6,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	}))

	c.AddChain(c.AddChain(&nftables.Chain{
		Name:     filterForwardChainName,
		Table:    nfTableV4,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	}))

	return Chains{
		V4FilterInput: filterInputChainV4,
		V6FilterInput: filterInputChainV6,
	}
}

// Chains is the list of chains to be used for rules.
type Chains struct {
	V4FilterInput *nftables.Chain
	V6FilterInput *nftables.Chain
}

// RuleSource generates firewall rules.
type RuleSource func(chains Chains) []*nftables.Rule
