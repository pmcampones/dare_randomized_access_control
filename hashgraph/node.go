package hashgraph

import (
	. "github.com/google/uuid"
	"math/rand"
)

type node struct {
	id   UUID
	op   func() error
	prev []*node
	next []*node
}

func newNode(op func() error, prev []*node) *node {
	n := &node{
		id:   New(),
		op:   op,
		prev: prev,
		next: make([]*node, len(prev)),
	}
	for _, p := range prev {
		p.addNext(n)
	}
	return n
}

func (n *node) addNext(nxt *node) {
	n.next = append(n.next, nxt)
}

func (n *node) runHashgraph(seed int) {
	r := rand.New(rand.NewSource(int64(seed)))
	readyToRun := make([]*node, 0)
	readyToRun = append(readyToRun, n)
	for len(readyToRun) > 0 {
		curr := readyToRun[0]
		err := curr.op()
		if err != nil {
			panic(err)
		}
		nxt := make([]*node, len(curr.next))
		for _, nxtNode := range curr.next {
			nxt = append(nxt, nxtNode)
		}
		r.Shuffle(len(nxt), func(i, j int) { nxt[i], nxt[j] = nxt[j], nxt[i] })
		readyToRun = append(readyToRun, nxt...)
	}
}
