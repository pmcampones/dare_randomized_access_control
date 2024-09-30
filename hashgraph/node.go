package hashgraph

import (
	. "github.com/google/uuid"
	"github.com/samber/lo"
	"math/rand"
)

type Node struct {
	id    UUID
	depth int
	op    func() error
	prev  []*Node
	next  []*Node
}

func NewNode(op func() error, prev []*Node) *Node {
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
		op:    op,
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
	readyToRun := make([]*Node, 0)
	readyToRun = append(readyToRun, n)
	for len(readyToRun) > 0 {
		curr := readyToRun[0]
		err := curr.op()
		if err != nil {
			panic(err)
		}
		nxt := make([]*Node, 0, len(curr.next))
		for _, nxtNode := range curr.next {
			nxt = append(nxt, nxtNode)
		}
		r.Shuffle(len(nxt), func(i, j int) { nxt[i], nxt[j] = nxt[j], nxt[i] })
		readyToRun = append(readyToRun[1:], nxt...)
	}
}
