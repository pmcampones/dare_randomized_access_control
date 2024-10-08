package hashgraph

import (
	. "github.com/google/uuid"
	"github.com/negrel/assert"
	"github.com/samber/lo"
	"log/slog"
	"maps"
	"math/rand"
	"slices"
)

type Node interface {
	GetId() UUID
	GetNext() []Node
	ExecFunc() error
}

type OpNode struct {
	id    UUID
	depth int
	exec  func() error
	prev  []*OpNode
	next  []*OpNode
}

func (n *OpNode) GetId() UUID {
	return n.id
}

func (n *OpNode) GetNext() []Node {
	return lo.Map(n.next, func(n *OpNode, i int) Node { return n })
}

func (n *OpNode) ExecFunc() error {
	return n.exec()
}

func NewNode(op func(depth int, id UUID, prevIds []UUID) error, prev []*OpNode) *OpNode {
	var depth int
	if prev == nil {
		prev = make([]*OpNode, 0)
		depth = 0
	} else {
		depth = 1 + lo.Max(lo.Map(prev, func(p *OpNode, _ int) int { return p.depth }))
	}
	id := New()
	prevIds := lo.Map(prev, func(p *OpNode, _ int) UUID { return p.id })
	n := &OpNode{
		id:    id,
		depth: depth,
		exec:  func() error { return op(depth, id, prevIds) },
		prev:  prev,
		next:  make([]*OpNode, 0),
	}
	for _, p := range prev {
		p.addNext(n)
	}
	return n
}

func (n *OpNode) addNext(nxt *OpNode) {
	n.next = append(n.next, nxt)
}

func RunHashgraph(seed int, n Node) {
	r := rand.New(rand.NewSource(int64(seed)))
	scheduleOrder := []Node{n}
	scheduled := make(map[UUID]bool)
	scheduled[n.GetId()] = true
	executed := make(map[UUID]bool)
	for len(scheduleOrder) > 0 {
		curr := scheduleOrder[0]
		err := curr.ExecFunc()
		if err != nil {
			slog.Error("Error executing operation", "err", err)
		}
		executed[curr.GetId()] = true
		nxt := make([]Node, 0, len(curr.GetNext()))
		for _, nxtNode := range curr.GetNext() {
			if !scheduled[nxtNode.GetId()] {
				nxt = append(nxt, nxtNode)
				scheduled[nxtNode.GetId()] = true
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

func listContains(big map[UUID]bool, small []Node) bool {
	ids := lo.Map(small, func(n Node, _ int) UUID { return n.GetId() })
	return lo.EveryBy(ids, func(id UUID) bool { return big[id] })
}

func isDisjoint(col1 map[UUID]bool, col2 []Node) bool {
	ids := lo.Map(col2, func(n Node, _ int) UUID { return n.GetId() })
	return lo.NoneBy(ids, func(id UUID) bool { return col1[id] })
}
