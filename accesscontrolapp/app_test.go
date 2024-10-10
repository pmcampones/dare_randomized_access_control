package accesscontrolapp

import (
	"dare_randomized_access_control/hashgraph"
	"fmt"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"math/rand"
	"testing"
)

func TestShouldStartEmpty(t *testing.T) {
	crdt := NewCRDT()
	app, err := ExecuteCRDT(&crdt, 10, 2)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(app.users))
	assert.Equal(t, 0, len(app.msgs))
}

func TestShouldHaveInitialNode(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, 100, 2)
	assert.NoError(t, err)
	assert.Equal(t, firstId, app.users[firstId].Id)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldRecordMessage(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	msg := "A"
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Post(firstId, msg), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, 100, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.msgs))
	assert.Equal(t, firstId, app.msgs[0].Issuer)
	assert.Equal(t, msg, app.msgs[0].Content)
}

func TestShouldAddPeer(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	points := 100
	hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, points/2)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(app.users))
	assert.Equal(t, firstId, app.users[firstId].Id)
	assert.Equal(t, secondId, app.users[secondId].Id)
}

func TestShouldGivePointsDuringAdd(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := 100
	givenPoints := makePtRange(0, points/2)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Add(firstId, secondId, "", givenPoints), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, len(givenPoints), app.users[secondId].Points.Len())
	assert.Equal(t, points-len(givenPoints), app.users[firstId].Points.Len())
}

func TestShouldRemovePeer(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	points := 100
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, points/2)), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{addNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
	assert.Equal(t, secondId, app.users[secondId].Id)
}

func TestShouldTakePointsDuringRem(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := 100
	givenPoints := makePtRange(0, points/2)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, "", givenPoints), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{addNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, points, app.users[secondId].Points.Len())
}

func TestShouldFailToPostMessageIssuerNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Post(secondId, "I don't exist yet"), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, 100, 2)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(app.msgs))
}

func TestShouldFailToAddPeerIssuerNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := 100
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	thirdId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Add(secondId, thirdId, "", makePtRange(0, points/2)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailToAddPeerAlreadyExistsSequential(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := 100
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	secondNode := hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, points/2)), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, 1)), []*hashgraph.OpNode{secondNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(app.users))
}

func TestShouldFailToAddPeerAlreadyExistsConcurrent(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := 100
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, 500)), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, 1)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(app.users))
}

func TestShouldFailToAddPeerLackOfPoints(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := makePtRange(0, 100)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Add(firstId, firstId, "", append(points, 1001)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, len(points), 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailToAddPeerCannotAddSelf(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := 100
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Add(firstId, firstId, "", makePtRange(0, 1)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailToAddPeerMustGivePoints(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := 100
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Add(firstId, secondId, "", []uint{}), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailRemovePeerIssuerNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, 100, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailRemovePeerUserNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	hashgraph.NewNode(crdt.Rem(firstId, secondId), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, 100, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldAddUsersConcurrently(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	ids := genIds(points-1, r)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	for i, id := range ids {
		hashgraph.NewNode(crdt.Add(firstId, id, "", []uint{uint(i)}), []*hashgraph.OpNode{firstNode})
	}
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, len(ids)+1, len(app.users))
	assert.True(t, lo.EveryBy(ids, func(id uuid.UUID) bool { return app.users[id] != nil }))
}

func TestShouldPostConcurrently(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	ids := genIds(points-1, r)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	for i, id := range ids {
		addNode := hashgraph.NewNode(crdt.Add(firstId, id, "", []uint{uint(i)}), []*hashgraph.OpNode{firstNode})
		hashgraph.NewNode(crdt.Post(id, "concurrent post"), []*hashgraph.OpNode{addNode})
	}
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, len(ids), len(app.msgs))
}

func TestShouldRemoveNonConflictingConcurrently(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	ids := genIds(points-1, r)
	ids2 := make([]uuid.UUID, 0, len(ids))
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	for i, id := range ids {
		addId := hashgraph.NewNode(crdt.Add(firstId, id, "", []uint{uint(2 * i), uint(2*i + 1)}), []*hashgraph.OpNode{firstNode})
		id2, err := uuid.NewRandomFromReader(r)
		assert.NoError(t, err)
		ids2 = append(ids2, id2)
		addId2 := hashgraph.NewNode(crdt.Add(id, id2, "", []uint{uint(2 * i)}), []*hashgraph.OpNode{addId})
		hashgraph.NewNode(crdt.Rem(id2, id), []*hashgraph.OpNode{addId2})
	}
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points*2, 2)
	assert.NoError(t, err)
	assert.Equal(t, int(points), len(app.users))
	assert.True(t, lo.NoneBy(ids, func(id uuid.UUID) bool { return app.users[id] != nil }))
	assert.True(t, lo.EveryBy(ids2, func(id uuid.UUID) bool { return app.users[id] != nil }))
}

func TestShouldRemoveConflictingConcurrently(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, 1)), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{addNode})
	hashgraph.NewNode(crdt.Rem(firstId, secondId), []*hashgraph.OpNode{addNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldRemoveLowerDepthFirst(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, "", []uint{0}), []*hashgraph.OpNode{firstNode})
	postNode := hashgraph.NewNode(crdt.Post(firstId, "placeholder"), []*hashgraph.OpNode{addNode})
	hashgraph.NewNode(crdt.Rem(firstId, secondId), []*hashgraph.OpNode{postNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{addNode})
	hashgraph.RunHashgraph(0, firstNode)
	points := 101
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
	assert.NotEqual(t, nil, app.users[secondId])
	assert.Equal(t, points, app.users[secondId].Points.Len())
}

func TestShouldHandleThreeWayConcurrentRemovals(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)
	//A removes B, B removes C, and C removes A. D observes the result
	r := rand.New(rand.NewSource(int64(25)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	thirdId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	watcherId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 101
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	add1Node := hashgraph.NewNode(crdt.Add(firstId, secondId, "", makePtRange(0, points/3)), []*hashgraph.OpNode{firstNode})
	add2Node := hashgraph.NewNode(crdt.Add(firstId, thirdId, "", makePtRange(points/3, 2*points/3)), []*hashgraph.OpNode{add1Node})
	add3Node := hashgraph.NewNode(crdt.Add(firstId, watcherId, "", []uint{uint(points - 1)}), []*hashgraph.OpNode{add2Node})
	remAB := hashgraph.NewNode(crdt.Rem(firstId, secondId), []*hashgraph.OpNode{add3Node})
	remBA := hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{add3Node})
	remBC := hashgraph.NewNode(crdt.Rem(secondId, thirdId), []*hashgraph.OpNode{add3Node})
	remCB := hashgraph.NewNode(crdt.Rem(thirdId, secondId), []*hashgraph.OpNode{add3Node})
	remAC := hashgraph.NewNode(crdt.Rem(firstId, thirdId), []*hashgraph.OpNode{add3Node})
	remCA := hashgraph.NewNode(crdt.Rem(thirdId, firstId), []*hashgraph.OpNode{add3Node})
	hashgraph.NewNode(crdt.Post(watcherId, "placeholder"), []*hashgraph.OpNode{remAB, remBA, remBC, remCB, remAC, remCA})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(app.users))
	fmt.Println(firstId)
	fmt.Println(secondId)
	fmt.Println(thirdId)
	fmt.Println(watcherId)
	fmt.Println(app.users)
}

func TestShouldBeAbleToReferenceFailedPost(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	failedPost := hashgraph.NewNode(crdt.Post(secondId, "I don't exist"), []*hashgraph.OpNode{firstNode})
	correctMsg := "I exist"
	hashgraph.NewNode(crdt.Post(firstId, correctMsg), []*hashgraph.OpNode{failedPost})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.msgs))
	assert.Equal(t, correctMsg, app.msgs[0].Content)
}

func TestShouldBeAbleToReferenceFailedAdd(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	failedAdd := hashgraph.NewNode(crdt.Add(secondId, firstId, "", []uint{0}), []*hashgraph.OpNode{firstNode})
	correctMsg := "I exist"
	hashgraph.NewNode(crdt.Post(firstId, correctMsg), []*hashgraph.OpNode{failedAdd})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.msgs))
	assert.Equal(t, correctMsg, app.msgs[0].Content)
}

func TestShouldBeAbleToReferenceFailedRem(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	failedRem := hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{firstNode})
	correctMsg := "I exist"
	hashgraph.NewNode(crdt.Post(firstId, correctMsg), []*hashgraph.OpNode{failedRem})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.msgs))
	assert.Equal(t, correctMsg, app.msgs[0].Content)
}

func TestShouldBeAbleToReferenceFailedConcurrentRem(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	thirdId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := 100
	firstNode := hashgraph.NewNode(crdt.Init(firstId, ""), nil)
	failedRem1 := hashgraph.NewNode(crdt.Rem(secondId, thirdId), []*hashgraph.OpNode{firstNode})
	failedRem2 := hashgraph.NewNode(crdt.Rem(thirdId, secondId), []*hashgraph.OpNode{firstNode})
	correctMsg := "I exist"
	hashgraph.NewNode(crdt.Post(firstId, correctMsg), []*hashgraph.OpNode{failedRem1, failedRem2})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt, points, 2)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.msgs))
	assert.Equal(t, correctMsg, app.msgs[0].Content)
}

func makePtRange(start, end int) []uint {
	return lo.Map(lo.RangeFrom(start, end-start), func(i, _ int) uint { return uint(i) })
}
