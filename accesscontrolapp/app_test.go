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
	firstNode.RunHashgraph(0)
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
	hashgraph.NewNode(crdt.Post(firstId, msg), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
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
	hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(500)), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
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
	hashgraph.NewNode(crdt.Add(firstId, secondId, givenPoints), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
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
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(500)), []*hashgraph.Node{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.Node{addNode})
	firstNode.RunHashgraph(0)
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
	addNode := hashgraph.NewNode(crdt.Add(firstId, secondId, givenPoints), []*hashgraph.Node{firstNode})
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.Node{addNode})
	firstNode.RunHashgraph(0)
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
	hashgraph.NewNode(crdt.Post(secondId, "I don't exist yet"), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
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
	hashgraph.NewNode(crdt.Add(secondId, thirdId, uint32(500)), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
}

func TestShouldFailToAddPeerAlreadyExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	secondNode := hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(500)), []*hashgraph.Node{firstNode})
	hashgraph.NewNode(crdt.Add(firstId, secondId, uint32(1)), []*hashgraph.Node{secondNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
}

func TestShouldFailToAddPeerLackOfPoints(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	hashgraph.NewNode(crdt.Add(firstId, firstId, points+1), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
}

func TestShouldFailToAddPeerCannotAddSelf(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	points := uint32(1000)
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, points), nil)
	hashgraph.NewNode(crdt.Add(firstId, firstId, 1), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
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
	hashgraph.NewNode(crdt.Add(firstId, secondId, 0), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
}

func TestShouldFailRemovePeerIssuerNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(1000)), nil)
	hashgraph.NewNode(crdt.Rem(secondId, firstId), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
}

func TestShouldFailRemovePeerUserNotExists(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	crdt := NewCRDT()
	firstId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	secondId, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	firstNode := hashgraph.NewNode(crdt.Init(firstId, uint32(1000)), nil)
	hashgraph.NewNode(crdt.Rem(firstId, secondId), []*hashgraph.Node{firstNode})
	firstNode.RunHashgraph(0)
	_, err = ExecuteCRDT(&crdt)
	assert.Error(t, err)
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
		hashgraph.NewNode(crdt.Add(firstId, id, 1), []*hashgraph.Node{firstNode})
	}
	firstNode.RunHashgraph(0)
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
		addNode := hashgraph.NewNode(crdt.Add(firstId, id, 1), []*hashgraph.Node{firstNode})
		hashgraph.NewNode(crdt.Post(id, "concurrent post"), []*hashgraph.Node{addNode})
	}
	firstNode.RunHashgraph(0)
	app, err := ExecuteCRDT(&crdt)
	assert.NoError(t, err)
	assert.Equal(t, len(ids), len(app.msgs))
}
