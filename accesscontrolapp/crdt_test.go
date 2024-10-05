package accesscontrolapp

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestLowerDepthShouldGoFirst(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	ids := genIds(100000, r)
	crdt := NewCRDT()
	maxDepth := 100
	repetitions := 20
	ops := genOperations(maxDepth, ids, repetitions, r, crdt)
	execOpsRandomOrder(t, r, ops)
	testOrderByDepth(t, crdt, maxDepth, repetitions, ids)
}

func testOrderByDepth(t *testing.T, crdt CRDT, maxDepth int, repetitions int, ids []uuid.UUID) {
	opList := crdt.GetOperationList()
	for d := 0; d < maxDepth; d++ {
		for i := 0; i < 3*repetitions; i++ {
			op := opList[d*3*repetitions+i]
			switch op.content.(type) {
			case *AddOp:
				addOp := op.content.(*AddOp)
				assert.Equal(t, ids[d], addOp.issuer)
				break
			case *RemOp:
				remOp := op.content.(*RemOp)
				assert.Equal(t, ids[d], remOp.issuer)
				break
			case *PostOp:
				postOp := op.content.(*PostOp)
				assert.Equal(t, ids[d], postOp.poster)
			}
		}
	}
}

func genOperations(maxDepth int, ids []uuid.UUID, repetitions int, r *rand.Rand, crdt CRDT) []func() error {
	ops := make([]func() error, 0, maxDepth*3*repetitions)
	for d := 0; d < maxDepth; d++ {
		issuer := ids[d]
		for i := 0; i < repetitions; i++ {
			added := ids[r.Intn(len(ids))]
			points := r.Intn(1000)
			exec := func() error {
				return crdt.Add(issuer, added, uint32(points))(d)
			}
			ops = append(ops, exec)
		}
		for i := 0; i < repetitions; i++ {
			rem := ids[r.Intn(len(ids))]
			exec := func() error {
				return crdt.Rem(issuer, rem)(d)
			}
			ops = append(ops, exec)
		}
		for i := 0; i < repetitions; i++ {
			msg := fmt.Sprintf("%d%d", d, i)
			exec := func() error {
				return crdt.Post(issuer, msg)(d)
			}
			ops = append(ops, exec)
		}
	}
	return ops
}

func TestRemBeforeAddBeforePost(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	repetitions := 20
	ops := make([]func() error, 0, 3*repetitions)
	for i := 0; i < repetitions; i++ {
		ops = append(ops, addRandom(t, r, crdt))
		ops = append(ops, remRandom(t, r, crdt))
		ops = append(ops, postRandom(t, r, crdt))
	}
	execOpsRandomOrder(t, r, ops)
	opList := crdt.GetOperationList()
	for i := 0; i < repetitions; i++ {
		assert.Equal(t, Rem, opList[i].kind)
	}
	for i := 0; i < repetitions; i++ {
		assert.Equal(t, Add, opList[i+repetitions].kind)
	}
	for i := 0; i < repetitions; i++ {
		assert.Equal(t, Post, opList[i+2*repetitions].kind)
	}
}

func remRandom(t *testing.T, r *rand.Rand, crdt CRDT) func() error {
	issuer, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	added, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	return func() error {
		return crdt.Rem(issuer, added)(0)
	}
}

func addRandom(t *testing.T, r *rand.Rand, crdt CRDT) func() error {
	issuer, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	added, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := r.Intn(1000)
	return func() error {
		return crdt.Add(issuer, added, uint32(points))(0)
	}
}

func postRandom(t *testing.T, r *rand.Rand, crdt CRDT) func() error {
	issuer, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	return func() error {
		return crdt.Post(issuer, fmt.Sprintf("%d", r.Int()))(0)
	}
}

func TestConflictingRemsShouldGoTogether(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	ids := genIds(1000000, r)
	crdt := NewCRDT()
	repetitions := 100
	ops := make([]func() error, 0, 2*repetitions)
	for i := 0; i < repetitions; i++ {
		ops = append(ops, genConflictingRems(ids, r, crdt)...)
	}
	execOpsRandomOrder(t, r, ops)
	opList := crdt.GetOperationList()
	for i := 0; i < 2*repetitions; i += 2 {
		rem0 := opList[i].content.(*RemOp)
		rem1 := opList[i+1].content.(*RemOp)
		assert.Equal(t, rem0.issuer, rem1.removed)
		assert.Equal(t, rem0.removed, rem1.issuer)
	}
}

func genConflictingRems(ids []uuid.UUID, r *rand.Rand, crdt CRDT) []func() error {
	id0 := ids[r.Intn(len(ids))]
	id1 := ids[r.Intn(len(ids))]
	rem0 := func() error {
		return crdt.Rem(id0, id1)(0)
	}
	rem1 := func() error {
		return crdt.Rem(id1, id0)(0)
	}
	return []func() error{rem0, rem1}
}

func genIds(num int, r *rand.Rand) []uuid.UUID {
	ids := make([]uuid.UUID, 0, num)
	for i := 0; i < num; i++ {
		id, err := uuid.NewRandomFromReader(r)
		if err != nil {
			panic(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func execOpsRandomOrder(t *testing.T, r *rand.Rand, ops []func() error) {
	r.Shuffle(len(ops), func(i, j int) { ops[i], ops[j] = ops[j], ops[i] })
	for _, op := range ops {
		err := op()
		assert.NoError(t, err)
	}
}
