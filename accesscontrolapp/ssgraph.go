package accesscontrolapp

import (
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
	id    uuid.UUID
	delta []*point
	prev  []*backnode
}

type forwardnode struct {
	id    uuid.UUID
	delta []*point
	next  []*forwardnode
}

func (n *forwardnode) GetId() uuid.UUID {
	return n.id
}

func (n *forwardnode) GetNext() []hashgraph.Node {
	return lo.Map(n.next, func(n *forwardnode, i int) hashgraph.Node { return n })
}

func (n *forwardnode) ExecFunc() error {
	return nil //TODO: implement
}

func initNode(shares []secretsharing.Share, firstNode uuid.UUID) *backnode {
	points := lo.Map(shares, func(s secretsharing.Share, _ int) *point {
		return &point{
			owner: firstNode,
			val:   s,
		}
	})
	return &backnode{
		id:    firstNode,
		delta: points,
	}
}

func addNode(id uuid.UUID, delta []*point, prev []*backnode) *backnode {
	return &backnode{
		id:    id,
		delta: delta,
		prev:  prev,
	}
}

// Assumes no cycles in the graph and no path existing between the nodes in the argument
func makeSubgraph(nodes []*backnode) *forwardnode {
	forward := make(map[uuid.UUID]*forwardnode)
	frontier := nodes
	var prevFrontier []*backnode
	for _, node := range nodes {
		fnode := forwardnode{
			id:    node.id,
			delta: node.delta,
			next:  []*forwardnode{},
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
					id:    p.id,
					delta: p.delta,
					next:  []*forwardnode{},
				}
				forward[p.id] = fnode
			}
			fnode.next = append(fnode.next, nxtfnode)
		}
	}
}

func (fnode *forwardnode) computeShareState() {
	hashgraph.RunHashgraph(0, fnode)
}
