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
	nfTable := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	c.AddTable(nfTable)

	filterInputChain := c.AddChain(&nftables.Chain{
		Name:     filterInputChainName,
		Table:    nfTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	})
	c.AddChain(filterInputChain)

	c.AddRule(&nftables.Rule{
		Table: nfTable,
		Chain: filterInputChain,
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

	c.AddChain(c.AddChain(&nftables.Chain{
		Name:     filterOutputChainName,
		Table:    nfTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyAccept),
	}))

	c.AddChain(c.AddChain(&nftables.Chain{
		Name:     filterForwardChainName,
		Table:    nfTable,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   lo.ToPtr(nftables.ChainPolicyDrop),
	}))

	return Chains{
		FilterInput: filterInputChain,
	}
}

// Chains is the list of chains to be used for rules.
type Chains struct {
	FilterInput *nftables.Chain
}

// RuleSource generates firewall rules.
type RuleSource func(chains Chains) []*nftables.Rule
