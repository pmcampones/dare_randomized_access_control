package hashgraph

import (
	. "github.com/google/uuid"
	"github.com/negrel/assert"
	"github.com/samber/lo"
	"maps"
	"math/rand"
	"slices"
)

type Node struct {
	id    UUID
	depth int
	exec  func() error
	prev  []*Node
	next  []*Node
}

func NewNode(op func(depth int) error, prev []*Node) *Node {
	var depth int
	if prev == nil {
		prev = make([]*Node, 0)
		depth = 0
	} else {
		depth = 1 + lo.Max(lo.Map(prev, func(p *Node, _ int) int { return p.depth }))
	}
	n := &Node{
		id:    New(),
		depth: depth,
		exec:  func() error { return op(depth) },
		prev:  prev,
		next:  make([]*Node, 0),
	}
	for _, p := range prev {
		p.addNext(n)
	}
	return n
}

func (n *Node) addNext(nxt *Node) {
	n.next = append(n.next, nxt)
}

func (n *Node) RunHashgraph(seed int) {
	r := rand.New(rand.NewSource(int64(seed)))
	scheduleOrder := []*Node{n}
	scheduled := make(map[UUID]bool)
	scheduled[n.id] = true
	executed := make(map[UUID]bool)
	for len(scheduleOrder) > 0 {
		curr := scheduleOrder[0]
		err := curr.exec()
		if err != nil {
			panic(err)
		}
		executed[curr.id] = true
		nxt := make([]*Node, 0, len(curr.next))
		for _, nxtNode := range curr.next {
			if canScheduleNode(nxtNode, executed, scheduled) {
				nxt = append(nxt, nxtNode)
				scheduled[nxtNode.id] = true
			}
		}
		r.Shuffle(len(nxt), func(i, j int) { nxt[i], nxt[j] = nxt[j], nxt[i] })
		scheduleOrder = append(scheduleOrder[1:], nxt...)

		// Assertions only run if the tag "assert" is used. e.g. go run -tags assert .
		assert.True(setContains(scheduled, executed), "All messages executed must have been scheduled")
		assert.True(listContains(scheduled, scheduleOrder), "All messages ordered to must must have been flagged to do so")
		assert.True(isDisjoint(executed, scheduleOrder), "No operation to be executed must have been executed before")
	}
}

func setContains(big, small map[UUID]bool) bool {
	ids := slices.Collect(maps.Keys(small))
	return lo.EveryBy(ids, func(id UUID) bool { return big[id] })
}

func listContains(big map[UUID]bool, small []*Node) bool {
	ids := lo.Map(small, func(n *Node, _ int) UUID { return n.id })
	return lo.EveryBy(ids, func(id UUID) bool { return big[id] })
}

func isDisjoint(col1 map[UUID]bool, col2 []*Node) bool {
	ids := lo.Map(col2, func(n *Node, _ int) UUID { return n.id })
	return lo.NoneBy(ids, func(id UUID) bool { return col1[id] })
}

func canScheduleNode(n *Node, executed map[UUID]bool, scheduled map[UUID]bool) bool {
	return !scheduled[n.id] && lo.EveryBy(n.prev, func(p *Node) bool {
		return executed[p.id]
	})
}
