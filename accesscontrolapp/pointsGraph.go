package accesscontrolapp

import (
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
	delta []*point
	next  []*forwardnode
}

func initNode(shares []secretsharing.Share, firstNode uuid.UUID) *backnode {
	points := lo.Map(shares, func(s secretsharing.Share, _ int) *point {
		return &point{
			owner: firstNode,
			val:   s,
		}
	})
	return &backnode{
		id:    uuid.New(),
		delta: points,
	}
}

func addNode(delta []*point, prev []*backnode) *backnode {
	return &backnode{
		id:    uuid.New(),
		delta: delta,
		prev:  prev,
	}
}

func makeSubgraph(nodes []*backnode) *forwardnode {
	forward := make(map[uuid.UUID]*forwardnode)
	frontier := nodes
	for _, node := range nodes {
		fnode := forwardnode{
			delta: node.delta,
			next:  []*forwardnode{},
		}
		forward[node.id] = &fnode
	}
	for len(frontier) > 0 {
		updateForwardNodes(frontier, forward)
		frontier = updateFrontier(nodes)
	}
	return nil
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
					delta: p.delta,
					next:  []*forwardnode{},
				}
				forward[p.id] = fnode
			}
			fnode.next = append(fnode.next, nxtfnode)
		}
	}
}
