package accesscontrolapp

import (
	"github.com/cloudflare/circl/secretsharing"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestShouldBeSingleBNode(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	id, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	bnode := initNode([]secretsharing.Share{}, id)
	assert.Equal(t, bnode.id, id)
	assert.Empty(t, bnode.prev)
}

func TestShouldFollowInitial(t *testing.T) {
	firstNode := initNode([]secretsharing.Share{}, uuid.New())
	secondNode := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	assert.Equal(t, 1, len(secondNode.prev))
	assert.Equal(t, firstNode, secondNode.prev[0])
}

func TestManyShouldFollowInitial(t *testing.T) {
	firstNode := initNode([]secretsharing.Share{}, uuid.New())
	curr := firstNode
	for i := 0; i < 100; i++ {
		curr = addNode(uuid.New(), []*point{}, []*backnode{curr})
	}
	for len(curr.prev) > 0 {
		assert.Equal(t, 1, len(curr.prev))
		curr = curr.prev[0]
	}
	assert.Equal(t, firstNode, curr)
}

func TestShouldFork(t *testing.T) {
	firstNode := initNode([]secretsharing.Share{}, uuid.New())
	upFork := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	downFork := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	last := addNode(uuid.New(), []*point{}, []*backnode{upFork, downFork})
	assert.Equal(t, 2, len(last.prev))
	assert.Equal(t, firstNode, last.prev[0].prev[0])
	assert.Equal(t, firstNode, last.prev[1].prev[0])
}

func TestShouldMakeSingleNodeForwardGraph(t *testing.T) {
	bnode := initNode([]secretsharing.Share{}, uuid.New())
	fnode := makeSubgraph([]*backnode{bnode})
	assert.Equal(t, bnode.id, fnode.id)
}

func TestShouldMakeSimpleLongForwardGraph(t *testing.T) {
	bnodes := make([]*backnode, 0)
	currBNode := initNode([]secretsharing.Share{}, uuid.New())
	bnodes = append(bnodes, currBNode)
	for i := 0; i < 100; i++ {
		currBNode = addNode(uuid.New(), []*point{}, []*backnode{currBNode})
		bnodes = append(bnodes, currBNode)
	}
	fnode := makeSubgraph([]*backnode{currBNode})
	for i := 0; i < len(bnodes)-1; i++ {
		assert.Equal(t, 1, len(fnode.next))
		assert.Equal(t, bnodes[i].id, fnode.id)
		fnode = fnode.next[0]
	}
	assert.Equal(t, 0, len(fnode.next))
	assert.Equal(t, bnodes[len(bnodes)-1].id, fnode.id)
}

func TestShouldIgnoreFork(t *testing.T) {
	fork1Nodes := make([]*backnode, 0)
	fork2Nodes := make([]*backnode, 0)
	firstNode := initNode([]secretsharing.Share{}, uuid.New())
	currBNode := firstNode
	for i := 0; i < 100; i++ {
		currBNode = addNode(uuid.New(), []*point{}, []*backnode{currBNode})
		fork1Nodes = append(fork1Nodes, currBNode)
	}
	lastFork1 := currBNode
	currBNode = firstNode
	for i := 0; i < 100; i++ {
		currBNode = addNode(uuid.New(), []*point{}, []*backnode{currBNode})
		fork2Nodes = append(fork2Nodes, currBNode)
	}
	lastFork2 := currBNode
	fnode1 := makeSubgraph([]*backnode{lastFork1})
	assert.Equal(t, fnode1.id, firstNode.id)
	for i := 0; i < len(fork1Nodes); i++ {
		fnode1 = fnode1.next[0]
		assert.Equal(t, fork1Nodes[i].id, fnode1.id)
	}
	fnode2 := makeSubgraph([]*backnode{lastFork2})
	assert.Equal(t, fnode2.id, firstNode.id)
	for i := 0; i < len(fork2Nodes); i++ {
		fnode2 = fnode2.next[0]
		assert.Equal(t, fork2Nodes[i].id, fnode2.id)
	}
}

func TestShouldComputeNonTreeGraph(t *testing.T) {
	firstNode := initNode([]secretsharing.Share{}, uuid.New())
	upNode := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	downNode := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	up2Node := addNode(uuid.New(), []*point{}, []*backnode{upNode, downNode})
	down2Node := addNode(uuid.New(), []*point{}, []*backnode{upNode, downNode})
	fnode := makeSubgraph([]*backnode{up2Node, down2Node})
	assert.Equal(t, fnode.id, firstNode.id)
	assert.Equal(t, 2, len(fnode.next))
	assert.NotEqual(t, fnode.next[0].id, fnode.next[1].id)
	for _, nxt := range fnode.next {
		assert.Equal(t, 2, len(nxt.next))
		assert.NotEqual(t, nxt.next[0].id, nxt.next[1].id)
		assert.True(t, nxt.id == downNode.id || nxt.id == upNode.id)
		for _, nxt2 := range nxt.next {
			assert.Equal(t, 0, len(nxt2.next))
			assert.True(t, nxt2.id == up2Node.id || nxt2.id == down2Node.id)
		}
	}
}
