package accesscontrolapp

import (
	"dare_randomized_access_control/cointoss"
	"dare_randomized_access_control/hashgraph"
	"github.com/cloudflare/circl/secretsharing"
	"github.com/google/uuid"
	"github.com/negrel/assert"
	"github.com/samber/lo"
)

type point struct {
	owner uuid.UUID
	val   secretsharing.Share
}

type backnode struct {
	id             uuid.UUID
	deltaVals      []secretsharing.Share
	ownerTransfers []*ownerTransfer
	prev           []*backnode
}

type forwardnode struct {
	id             uuid.UUID
	deltaVals      []secretsharing.Share
	ownerTransfers []*ownerTransfer
	next           []*forwardnode
	accum          *graphState
}

type ownerTransfer struct {
	shareIdx uint
	owner    uuid.UUID
}

type graphState struct {
	points []*point
}

func (n *forwardnode) GetId() uuid.UUID {
	return n.id
}

func (n *forwardnode) GetNext() []hashgraph.Node {
	return lo.Map(n.next, func(n *forwardnode, i int) hashgraph.Node { return n })
}

func (n *forwardnode) ExecFunc() error {
	if len(n.accum.points) == 0 {
		n.fillInitial()
	} else {
		n.updateAccum()
	}
	return nil
}

func (n *forwardnode) fillInitial() {
	assert.Equal(len(n.deltaVals), len(n.ownerTransfers), "deltaVals and ownerTransfers must have the same length")
	n.accum.points = lo.ZipBy2(n.deltaVals, n.ownerTransfers, func(val secretsharing.Share, owner *ownerTransfer) *point {
		return &point{
			owner: owner.owner,
			val:   val,
		}
	})
}

func (n *forwardnode) updateAccum() {
	for _, ownerTransfer := range n.ownerTransfers {
		n.accum.points[ownerTransfer.shareIdx].owner = ownerTransfer.owner
	}
	if len(n.deltaVals) > 0 {
		for _, tuple := range lo.Zip2(n.deltaVals, n.accum.points) {
			val, pt := tuple.Unpack()
			pt.val.Value = cointoss.AddScalar(pt.val.Value, val.Value)
		}
	}
}

func initNode(shares []secretsharing.Share, firstNode, firstOwner uuid.UUID) *backnode {
	ownerTransfers := lo.Map(shares, func(_ secretsharing.Share, i int) *ownerTransfer {
		return &ownerTransfer{
			shareIdx: uint(i),
			owner:    firstOwner,
		}
	})
	return &backnode{
		id:             firstNode,
		deltaVals:      shares,
		ownerTransfers: ownerTransfers,
		prev:           []*backnode{},
	}
}

func addNode(id uuid.UUID, deltaVals []secretsharing.Share, ownerTransfers []*ownerTransfer, prev []*backnode) *backnode {
	return &backnode{
		id:             id,
		deltaVals:      deltaVals,
		ownerTransfers: ownerTransfers,
		prev:           prev,
	}
}

func getCurrentShares(nodes []*backnode) []secretsharing.Share {
	fnode := makeSubgraph(nodes)
	points := fnode.computeShareState()
	return lo.Map(points, func(p *point, _ int) secretsharing.Share { return p.val })
}

// Assumes no cycles in the graph and no path existing between the nodes in the argument
func makeSubgraph(nodes []*backnode) *forwardnode {
	gstate := &graphState{make([]*point, 0)}
	forward := make(map[uuid.UUID]*forwardnode)
	frontier := nodes
	var prevFrontier []*backnode
	for _, node := range nodes {
		fnode := forwardnode{
			id:             node.id,
			deltaVals:      node.deltaVals,
			ownerTransfers: node.ownerTransfers,
			next:           []*forwardnode{},
			accum:          gstate,
		}
		forward[node.id] = &fnode
	}
	for len(frontier) > 0 {
		updateForwardNodes(frontier, forward)
		prevFrontier = frontier
		frontier = updateFrontier(frontier)
	}
	return forward[prevFrontier[0].id]
}

func updateFrontier(nodes []*backnode) []*backnode {
	frontierNodes := make(map[uuid.UUID]*backnode)
	frontier := make([]*backnode, 0)
	for _, node := range nodes {
		for _, p := range node.prev {
			if frontierNodes[p.id] == nil {
				frontierNodes[p.id] = p
				frontier = append(frontier, p)
			}
		}
	}
	return frontier
}

func updateForwardNodes(frontier []*backnode, forward map[uuid.UUID]*forwardnode) {
	for _, node := range frontier {
		nxtfnode := forward[node.id]
		assert.NotEqual(nil, nxtfnode, "forward node must exist at this point")
		for _, p := range node.prev {
			fnode := forward[p.id]
			if fnode == nil {
				fnode = &forwardnode{
					id:             p.id,
					deltaVals:      p.deltaVals,
					ownerTransfers: p.ownerTransfers,
					next:           []*forwardnode{},
					accum:          nxtfnode.accum,
				}
				forward[p.id] = fnode
			}
			fnode.next = append(fnode.next, nxtfnode)
		}
	}
}

func (n *backnode) newForward(gs *graphState) *forwardnode {
	return &forwardnode{
		id:             n.id,
		deltaVals:      n.deltaVals,
		ownerTransfers: n.ownerTransfers,
		next:           []*forwardnode{},
		accum:          gs,
	}
}

func (n *forwardnode) computeShareState() []*point {
	hashgraph.RunHashgraph(0, n)
	return n.accum.points
}
