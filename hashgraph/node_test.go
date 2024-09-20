package hashgraph

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestShouldMakeNode(t *testing.T) {
	send := 'A'
	received := make([]int32, 0)
	n := NewNode(func() error {
		received = append(received, send)
		return nil
	}, nil)
	n.RunHashgraph(0)
	assert.Equal(t, 1, len(received))
	assert.Equal(t, send, received[0])
}

func TestShouldRunSequential(t *testing.T) {
	numNodes := 100
	send := make([]int32, 0, 100)
	for i := 0; i < numNodes; i++ {
		send = append(send, int32(i))
	}
	received := make([]int32, 0, numNodes)
	nodes := make([]*Node, 0, numNodes)
	nodes = append(nodes, NewNode(func() error {
		received = append(received, 0)
		return nil
	}, nil))
	for i := 1; i < numNodes; i++ {
		prev := []*Node{nodes[i-1]}
		nodes = append(nodes, NewNode(func() error {
			received = append(received, int32(i))
			return nil
		}, prev))
	}
	nodes[0].RunHashgraph(0)
	assert.Equal(t, numNodes, len(send))
	assert.Equal(t, len(send), len(received))
	for i := 0; i < numNodes; i++ {
		assert.Equal(t, send[i], received[i])
	}
}

func TestShouldRunConcurrent(t *testing.T) {
	numNodes := 1000
	received := make(map[int32]bool)
	firstNode := NewNode(func() error { return nil }, nil)
	for i := 0; i < numNodes; i++ {
		NewNode(func() error {
			received[int32(i)] = true
			return nil
		}, []*Node{firstNode})
	}
	firstNode.RunHashgraph(0)
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
	firstNode := NewNode(func() error { return nil }, nil)
	for i := 0; i < numNodes; i++ {
		NewNode(func() error {
			ch <- int32(i)
			return nil
		}, []*Node{firstNode})
	}
	go firstNode.RunHashgraph(0)
	for i := 0; i < numNodes; i++ {
		order1 = append(order1, <-ch)
	}
	go firstNode.RunHashgraph(0)
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
	firstNode := NewNode(func() error { return nil }, nil)
	for i := 0; i < numNodes; i++ {
		NewNode(func() error {
			ch <- int32(i)
			return nil
		}, []*Node{firstNode})
	}
	go firstNode.RunHashgraph(0)
	for i := 0; i < numNodes; i++ {
		order1 = append(order1, <-ch)
	}
	go firstNode.RunHashgraph(1)
	for i := 0; i < numNodes; i++ {
		order2 = append(order2, <-ch)
	}
	assert.Equal(t, numNodes, len(order1))
	assert.Equal(t, numNodes, len(order2))
	assert.NotEqual(t, order1, order2)
}
