package main

import (
	"dare_randomized_access_control/accesscontrolapp"
	"dare_randomized_access_control/hashgraph"
	"fmt"
	"github.com/google/uuid"
	"math/rand"
)

func main() {
	crdt := accesscontrolapp.NewCRDT()
	r := rand.New(rand.NewSource(int64(0)))
	alice, _ := uuid.NewRandomFromReader(r)
	initNode := hashgraph.NewNode(crdt.Init(alice, 100), nil)
	bob, _ := uuid.NewRandomFromReader(r)
	addBob := hashgraph.NewNode(crdt.Add(alice, bob, 20), []*hashgraph.OpNode{initNode})
	claire, _ := uuid.NewRandomFromReader(r)
	dillan, _ := uuid.NewRandomFromReader(r)
	addClaire := hashgraph.NewNode(crdt.Add(alice, claire, 20), []*hashgraph.OpNode{addBob})
	addDillan := hashgraph.NewNode(crdt.Add(bob, dillan, 20), []*hashgraph.OpNode{addBob})
	hashgraph.NewNode(crdt.Post(alice, "hello everyone"), []*hashgraph.OpNode{addClaire, addDillan})
	hashgraph.RunHashgraph(0, initNode)
	lst := crdt.GetOperationList()
	for _, op := range lst {
		fmt.Println(op)
	}
}
