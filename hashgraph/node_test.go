package hashgraph

import (
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestShouldMakeNode(t *testing.T) {
	send := 'A'
	received := make([]int32, 0)
	n := NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
		received = append(received, send)
		return nil
	}, nil)
	RunHashgraph(0, n)
	assert.Equal(t, 1, len(received))
	assert.Equal(t, send, received[0])
}

func TestShouldRunSequential(t *testing.T) {
	numNodes := 100
	send := make([]int32, 0, numNodes)
	for i := 0; i < numNodes; i++ {
		send = append(send, int32(i))
	}
	received := make([]int32, 0, numNodes)
	nodes := make([]*OpNode, 0, numNodes)
	nodes = append(nodes, NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
		received = append(received, 0)
		return nil
	}, nil))
	for i := 1; i < numNodes; i++ {
		prev := []*OpNode{nodes[i-1]}
		nodes = append(nodes, NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
			received = append(received, int32(i))
			return nil
		}, prev))
	}
	RunHashgraph(0, nodes[0])
	assert.Equal(t, numNodes, len(send))
	assert.Equal(t, len(send), len(received))
	for i := 0; i < numNodes; i++ {
		assert.Equal(t, send[i], received[i])
	}
}

func TestShouldRunConcurrent(t *testing.T) {
	numNodes := 1000
	received := make(map[int32]bool)
	firstNode := NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error { return nil }, nil)
	for i := 0; i < numNodes; i++ {
		NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
			received[int32(i)] = true
			return nil
		}, []*OpNode{firstNode})
	}
	RunHashgraph(0, firstNode)
	assert.Equal(t, numNodes, len(received))
	for i := 0; i < numNodes; i++ {
		assert.True(t, received[int32(i)])
	}
}

func TestShouldProduceSameOrder(t *testing.T) {
	numNodes := 1000
	order1 := make([]int32, 0, numNodes)
	order2 := make([]int32, 0, numNodes)
	ch := make(chan int32)
	firstNode := NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error { return nil }, nil)
	for i := 0; i < numNodes; i++ {
		NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
			ch <- int32(i)
			return nil
		}, []*OpNode{firstNode})
	}
	go RunHashgraph(0, firstNode)
	for i := 0; i < numNodes; i++ {
		order1 = append(order1, <-ch)
	}
	go RunHashgraph(0, firstNode)
	for i := 0; i < numNodes; i++ {
		order2 = append(order2, <-ch)
	}
	assert.Equal(t, numNodes, len(order1))
	assert.Equal(t, numNodes, len(order2))
	assert.Equal(t, order1, order2)
}

func TestShouldProduceDifferentOrder(t *testing.T) {
	numNodes := 1000
	order1 := make([]int32, 0, numNodes)
	order2 := make([]int32, 0, numNodes)
	ch := make(chan int32)
	firstNode := NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error { return nil }, nil)
	for i := 0; i < numNodes; i++ {
		NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
			ch <- int32(i)
			return nil
		}, []*OpNode{firstNode})
	}
	go RunHashgraph(0, firstNode)
	for i := 0; i < numNodes; i++ {
		order1 = append(order1, <-ch)
	}
	go RunHashgraph(1, firstNode)
	for i := 0; i < numNodes; i++ {
		order2 = append(order2, <-ch)
	}
	assert.Equal(t, numNodes, len(order1))
	assert.Equal(t, numNodes, len(order2))
	assert.NotEqual(t, order1, order2)
}

func TestShouldNotExecuteTwice(t *testing.T) {
	vals := []byte{'A', 'B', 'C', 'D'}
	executed := make([]byte, 0)
	firstNode := NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
		executed = append(executed, vals[0])
		return nil
	}, nil)
	upNode := NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
		executed = append(executed, vals[1])
		return nil
	}, []*OpNode{firstNode})
	downNode := NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
		executed = append(executed, vals[2])
		return nil
	}, []*OpNode{firstNode})
	NewNode(func(_ int, _ uuid.UUID, _ []uuid.UUID) error {
		executed = append(executed, vals[3])
		return nil
	}, []*OpNode{upNode, downNode})
	RunHashgraph(0, firstNode)
	assert.Equal(t, len(vals), len(executed))
}
