package accesscontrolapp

import (
	"dare_randomized_access_control/hashgraph"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestShouldStartEmpty(t *testing.T) {
	crdt := NewCRDT()
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(app.users))
	assert.Equal(t, 0, len(app.msgs))
}

func TestShouldHaveInitialNode(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(r.Int())), nil)
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
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
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(r.Int())), nil)
	hashgraph.NewNode(crdt.Post(firstId, msg), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
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
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(1000)), nil)
	hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(500)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(app.users))
	assert.Equal(t, firstId, app.users[firstId].Id)
	assert.Equal(t, secondId, app.users[secondId].Id)
}

func TestShouldGivePointsDuringAdd(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	initialPoints := uint32(1000)
	givenPoints := uint32(500)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, initialPoints), nil)
	hashgraph.NewNode(crdt.Add(firstId, secondId, givenPoints), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, givenPoints, app.users[secondId].Points)
	assert.Equal(t, initialPoints-givenPoints, app.users[firstId].Points)
}

func TestShouldRemovePeer(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(1000)), nil)
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(500)), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{addNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
	assert.Equal(t, secondId, app.users[secondId].Id)
}

func TestShouldTakePointsDuringRem(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	initialPoints := uint32(1000)
	givenPoints := uint32(500)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, initialPoints), nil)
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, givenPoints), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{addNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, initialPoints, app.users[secondId].Points)
}

func TestShouldFailToPostMessageIssuerNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(1000)), nil)
	hashgraph.NewNode(crdt.Post(secondId, "I don't exist yet"), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(app.msgs))
}

func TestShouldFailToAddPeerIssuerNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	thirdId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	hashgraph.NewNode(crdt.Add(secondId, thirdId, uint32(500)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailToAddPeerAlreadyExistsSequential(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	secondNode := hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(500)), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(1)), []*hashgraph.OpNode{secondNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(app.users))
}

func TestShouldFailToAddPeerAlreadyExistsConcurrent(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(500)), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(1)), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(app.users))
}

func TestShouldFailToAddPeerLackOfPoints(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	hashgraph.NewNode(crdt.Add(firstId, firstId, points+1), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailToAddPeerCannotAddSelf(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	hashgraph.NewNode(crdt.Add(firstId, firstId, 1), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldFailToAddPeerMustGivePoints(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	hashgraph.NewNode(crdt.Add(firstId, secondId, 0), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
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
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(1000)), nil)
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
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
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(1000)), nil)
	hashgraph.NewNode(crdt.Rem(firstId, secondId), []*hashgraph.OpNode{firstNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}

func TestShouldAddUsersConcurrently(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := uint32(1000)
	ids := genIds(int(points-1), r)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	for _, id := range ids {
		hashgraph.NewNode(crdt.Add(firstId, id, 1), []*hashgraph.OpNode{firstNode})
	}
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, len(ids)+1, len(app.users))
	assert.True(t, lo.EveryBy(ids, func(id uuid.UUID) bool { return app.users[id] != nil }))
}

func TestShouldPostConcurrently(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := uint32(1000)
	ids := genIds(int(points-1), r)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	for _, id := range ids {
		addNode := hashgraph.NewNode(crdt.Add(firstId, id, 1), []*hashgraph.OpNode{firstNode})
		hashgraph.NewNode(crdt.Post(id, "concurrent post"), []*hashgraph.OpNode{addNode})
	}
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, len(ids), len(app.msgs))
}

func TestShouldRemoveNonConflictingConcurrently(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	points := uint32(1000)
	ids := genIds(int(points-1), r)
	ids2 := make([]uuid.UUID, 0, len(ids))
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points*2), nil)
	for _, id := range ids {
		addId := hashgraph.NewNode(crdt.Add(firstId, id, 2), []*hashgraph.OpNode{firstNode})
		id2, err := uuid.NewRandomFromReader(r)
		assert.NoError(t, err)
		ids2 = append(ids2, id2)
		addId2 := hashgraph.NewNode(crdt.Add(id, id2, 1), []*hashgraph.OpNode{addId})
		hashgraph.NewNode(crdt.Rem(id2, id), []*hashgraph.OpNode{addId2})
	}
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
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
	points := uint32(1000)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, 1), []*hashgraph.OpNode{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.OpNode{addNode})
	hashgraph.NewNode(crdt.Rem(firstId, secondId), []*hashgraph.OpNode{addNode})
	hashgraph.RunHashgraph(0, firstNode)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(app.users))
}
