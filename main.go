package main

import (
	"dare_randomized_access_control/accesscontrolapp"
	"dare_randomized_access_control/hashgraph"
	"fmt"
	"github.com/google/uuid"
	"github.com/inancgumus/screen"
	"github.com/samber/lo"
	"log/slog"
	"math/rand"
	"strings"
	"time"
)

type programExecutor struct {
	crdt          accesscontrolapp.CRDT
	init          *hashgraph.OpNode
	threshold     int
	numPoints     int
	sleepInterval time.Duration
}

func main() {
	executor := &programExecutor{
		crdt:          accesscontrolapp.NewCRDT(),
		threshold:     2,
		numPoints:     1000,
		sleepInterval: 1 * time.Second,
	}
	err := executor.runProgram()
	if err != nil {
		fmt.Println(err)
	}
}

func (pe *programExecutor) runProgram() error {
	slog.SetLogLoggerLevel(slog.LevelError)
	r := rand.New(rand.NewSource(int64(3)))
	alice, _ := uuid.NewRandomFromReader(r)
	bob, _ := uuid.NewRandomFromReader(r)
	claire, _ := uuid.NewRandomFromReader(r)
	dillan, _ := uuid.NewRandomFromReader(r)
	secretPlayer, _ := uuid.NewRandomFromReader(r)
	pe.init = hashgraph.NewNode(pe.crdt.Init(alice, "Alice"), nil)
	_ = pe.runInstruction()
	addBob := hashgraph.NewNode(pe.crdt.Add(alice, bob, "Bob", pointRange(0, 20)), []*hashgraph.OpNode{pe.init})
	_ = pe.runInstruction()
	alicePost1 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: Hello Bob, I gave you 20 points please add Dillan and give him 10 points, I don't know his number :P"), []*hashgraph.OpNode{addBob})
	_ = pe.runInstruction()
	bobPost1 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: Aye aye captain!"), []*hashgraph.OpNode{alicePost1})
	_ = pe.runInstruction()
	addClaire := hashgraph.NewNode(pe.crdt.Add(alice, claire, "Claire", pointRange(20, 520)), []*hashgraph.OpNode{alicePost1})
	_ = pe.runInstruction()
	addDillan := hashgraph.NewNode(pe.crdt.Add(bob, dillan, "Dillan", pointRange(0, 5)), []*hashgraph.OpNode{bobPost1})
	_ = pe.runInstruction()
	bobPost2 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: How come Claire gets 500 points while I get 10 😠"), []*hashgraph.OpNode{addClaire, addDillan})
	_ = pe.runInstruction()
	alicePost2 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: 🤔 Let's see, maybe because Bob stands for Byzantine"), []*hashgraph.OpNode{bobPost2})
	_ = pe.runInstruction()
	clairePost1 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: And Claire stands for Correct 😊"), []*hashgraph.OpNode{alicePost2})
	_ = pe.runInstruction()
	dillanPost1 := hashgraph.NewNode(pe.crdt.Post(dillan, "Dillan: I think Bob the byzantine menace owes me 5 points"), []*hashgraph.OpNode{clairePost1})
	_ = pe.runInstruction()
	bobPost3 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: ... Changing topics, wasn't a message reordered up there"), []*hashgraph.OpNode{dillanPost1})
	_ = pe.runInstruction()
	clairePost2 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: Pedro programmed this, it's a miracle we're even part of the demo"), []*hashgraph.OpNode{bobPost3})
	_ = pe.runInstruction()
	alicePost3 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: 😂 Should we just add a bunch of users until we reach P?"), []*hashgraph.OpNode{clairePost2})
	_ = pe.runInstruction()
	alicePost4 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: Then we can question him?"), []*hashgraph.OpNode{alicePost3})
	_ = pe.runInstruction()
	dillanPost2 := hashgraph.NewNode(pe.crdt.Post(dillan, "Dillan: Guys I think my net is kinda weird!"), []*hashgraph.OpNode{dillanPost1})
	_ = pe.runInstruction()
	dillanPost3 := hashgraph.NewNode(pe.crdt.Post(dillan, "Dillan: Can you see my messages"), []*hashgraph.OpNode{dillanPost2})
	_ = pe.runInstruction()
	dillanPost4 := hashgraph.NewNode(pe.crdt.Post(dillan, "Dillan: Hellooo!! I'm all alone in the void 😭"), []*hashgraph.OpNode{dillanPost3})
	_ = pe.runInstruction()
	clairePost3 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: Hey Dillan! We read you loud and clear"), []*hashgraph.OpNode{dillanPost4, alicePost4})
	_ = pe.runInstruction()
	alicePost5 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: I guess Dillan stands for disconnected"), []*hashgraph.OpNode{clairePost3})
	_ = pe.runInstruction()
	bobPost4 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: Enough lollygag! The demo demands we get mad at each other 😠"), []*hashgraph.OpNode{alicePost5})
	_ = pe.runInstruction()
	alicePost6 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: Say no more 😈"), []*hashgraph.OpNode{bobPost4})
	_ = pe.runInstruction()
	remDilanAlice := hashgraph.NewNode(pe.crdt.Rem(dillan, alice), []*hashgraph.OpNode{alicePost6})
	_ = pe.runInstruction()
	dillanPost5 := hashgraph.NewNode(pe.crdt.Post(dillan, "Dillan: Hee Hee, got her first 😎"), []*hashgraph.OpNode{remDilanAlice})
	_ = pe.runInstruction()
	bobPost5 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: Good job bro!"), []*hashgraph.OpNode{dillanPost5})
	_ = pe.runInstruction()
	remAliceDilan := hashgraph.NewNode(pe.crdt.Rem(alice, dillan), []*hashgraph.OpNode{alicePost6})
	_ = pe.runInstruction()
	alicePost7 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: I'm back"), []*hashgraph.OpNode{bobPost5, remAliceDilan})
	_ = pe.runInstruction()
	clairePost4 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: I think she time traveled"), []*hashgraph.OpNode{alicePost7})
	_ = pe.runInstruction()
	bobPost6 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: Two of us can play that game. I'll save you Dillan"), []*hashgraph.OpNode{clairePost4})
	_ = pe.runInstruction()
	remBobAlice := hashgraph.NewNode(pe.crdt.Rem(bob, alice), []*hashgraph.OpNode{bobPost4})
	_ = pe.runInstruction()
	clairePost5 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: At least now we know Alice stands for A****le"), []*hashgraph.OpNode{remBobAlice, bobPost6})
	_ = pe.runInstruction()
	remAliceBob := hashgraph.NewNode(pe.crdt.Rem(alice, bob), []*hashgraph.OpNode{bobPost4})
	_ = pe.runInstruction()
	alicePost8 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: Want to remove me with those meager 10... wait, 15 points?"), []*hashgraph.OpNode{remAliceBob, clairePost5})
	_ = pe.runInstruction()
	clairePost6 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: Only way to beat her is to go back to the start."), []*hashgraph.OpNode{alicePost8})
	_ = pe.runInstruction()
	alicePost9 := hashgraph.NewNode(pe.crdt.Post(alice, "Alice: 50/50 chance, let's do it!!!!"), []*hashgraph.OpNode{clairePost6})
	_ = pe.runInstruction()
	remAliceClaire := hashgraph.NewNode(pe.crdt.Rem(alice, claire), []*hashgraph.OpNode{addClaire})
	_ = pe.runInstruction()
	remClaireAlice := hashgraph.NewNode(pe.crdt.Rem(claire, alice), []*hashgraph.OpNode{addClaire})
	_ = pe.runInstruction()
	bobPost7 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: Wow, that was close! 😵"), []*hashgraph.OpNode{remAliceClaire, remClaireAlice, alicePost9})
	_ = pe.runInstruction()
	clairePost7 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: Not really actually, Pedro controls the seed that decides our ids."), []*hashgraph.OpNode{bobPost7})
	_ = pe.runInstruction()
	dillanPost6 := hashgraph.NewNode(pe.crdt.Post(dillan, "Dillan: He just reruns the simulation until we win"), []*hashgraph.OpNode{clairePost7})
	_ = pe.runInstruction()
	bobPost8 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: And now?"), []*hashgraph.OpNode{dillanPost6})
	_ = pe.runInstruction()
	clairePost8 := hashgraph.NewNode(pe.crdt.Post(claire, "Claire: Now we rest Bob the brash"), []*hashgraph.OpNode{bobPost8})
	_ = pe.runInstruction()
	bobPost9 := hashgraph.NewNode(pe.crdt.Post(bob, "Bob: I hope they remember us fondly 😰"), []*hashgraph.OpNode{clairePost8})
	_ = pe.runInstruction()
	addClairePedro := hashgraph.NewNode(pe.crdt.Add(claire, secretPlayer, "Pedro", pointRange(100, 1)), []*hashgraph.OpNode{bobPost9})
	_ = pe.runInstruction()
	_ = hashgraph.NewNode(pe.crdt.Post(secretPlayer, "Pedro: I'm sure they will Bob. You were all truly wonderful"), []*hashgraph.OpNode{addClairePedro})
	_ = pe.runInstruction()
	return nil
}

func (pe *programExecutor) runInstruction() error {
	screen.Clear()
	screen.MoveTopLeft()
	seed := int(time.Now().UnixNano())
	hashgraph.RunHashgraph(seed, pe.init)
	app, err := accesscontrolapp.ExecuteCRDT(&pe.crdt, pe.numPoints, pe.threshold)
	if err != nil {
		return fmt.Errorf("error executing CRDT: %v", err)
	}
	msgs := lo.Map(app.Msgs, func(m accesscontrolapp.Msg, _ int) string { return m.Content })
	fmt.Println(strings.Join(msgs, "\n"))
	pe.crdt.Clear()
	time.Sleep(pe.sleepInterval)
	return nil
}

func pointRange(first, num int) []uint {
	return lo.Map(lo.Range(num), func(i int, _ int) uint { return uint(first + i) })
}
