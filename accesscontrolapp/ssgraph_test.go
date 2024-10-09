package accesscontrolapp

import (
	"dare_randomized_access_control/cointoss"
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
	"github.com/google/uuid"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestShouldBeSingleBNode(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	id, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	bnode := initNode([]secretsharing.Share{}, id, id)
	assert.Equal(t, bnode.id, id)
	assert.Empty(t, bnode.prev)
}

func TestShouldFollowInitial(t *testing.T) {
	firstNode := initNode([]secretsharing.Share{}, uuid.New(), uuid.New())
	secondNode := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	assert.Equal(t, 1, len(secondNode.prev))
	assert.Equal(t, firstNode, secondNode.prev[0])
}

func TestManyShouldFollowInitial(t *testing.T) {
	firstNode := initNode([]secretsharing.Share{}, uuid.New(), uuid.New())
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
	firstNode := initNode([]secretsharing.Share{}, uuid.New(), uuid.New())
	upFork := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	downFork := addNode(uuid.New(), []*point{}, []*backnode{firstNode})
	last := addNode(uuid.New(), []*point{}, []*backnode{upFork, downFork})
	assert.Equal(t, 2, len(last.prev))
	assert.Equal(t, firstNode, last.prev[0].prev[0])
	assert.Equal(t, firstNode, last.prev[1].prev[0])
}

func TestShouldMakeSingleNodeForwardGraph(t *testing.T) {
	bnode := initNode([]secretsharing.Share{}, uuid.New(), uuid.New())
	fnode := makeSubgraph([]*backnode{bnode})
	assert.Equal(t, bnode.id, fnode.id)
}

func TestShouldMakeSimpleLongForwardGraph(t *testing.T) {
	bnodes := make([]*backnode, 0)
	currBNode := initNode([]secretsharing.Share{}, uuid.New(), uuid.New())
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
	firstNode := initNode([]secretsharing.Share{}, uuid.New(), uuid.New())
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
	firstNode := initNode([]secretsharing.Share{}, uuid.New(), uuid.New())
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

func TestShouldReturnInitialPointsSingleNode(t *testing.T) {
	shares := lo.Map(lo.Range(100), func(i, _ int) secretsharing.Share {
		return secretsharing.Share{
			ID:    cointoss.NewScalar(uint64(i)),
			Value: cointoss.NewScalar(uint64(i)),
		}
	})
	firstNode := initNode(shares, uuid.New(), uuid.New())
	fnode := makeSubgraph([]*backnode{firstNode})
	points := fnode.computeShareState()
	recovShares := lo.Map(points, func(p *point, _ int) secretsharing.Share {
		return p.val
	})
	assert.Equal(t, shares, recovShares)
}

func TestShouldReturnInitialPointsLongChain(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	id, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	shares := lo.Map(lo.Range(100), func(i, _ int) secretsharing.Share {
		return secretsharing.Share{
			ID:    cointoss.NewScalar(uint64(i)),
			Value: cointoss.NewScalar(uint64(i)),
		}
	})
	firstNode := initNode(shares, uuid.New(), id)
	currBNode := firstNode
	for i := 0; i < 100; i++ {
		newPoints := lo.Map(shares, func(s secretsharing.Share, _ int) *point {
			return &point{
				owner: id,
				val: secretsharing.Share{
					ID:    s.ID,
					Value: cointoss.NewScalar(0),
				},
			}
		})
		currBNode = addNode(uuid.New(), newPoints, []*backnode{currBNode})
	}
	fnode := makeSubgraph([]*backnode{currBNode})
	points := fnode.computeShareState()
	recovShares := lo.Map(points, func(p *point, _ int) secretsharing.Share {
		return p.val
	})
	assert.Equal(t, shares, recovShares)
}

func TestShouldUpdatePointValsInLongChain(t *testing.T) {
	r := rand.New(rand.NewSource(int64(0)))
	id, err := uuid.NewRandomFromReader(r)
	assert.NoError(t, err)
	numUpdates := 100
	shares := lo.Map(lo.Range(100), func(i, _ int) secretsharing.Share {
		return secretsharing.Share{
			ID:    cointoss.NewScalar(uint64(i)),
			Value: cointoss.NewScalar(0),
		}
	})
	firstNode := initNode(shares, uuid.New(), id)
	currBNode := firstNode
	for i := 0; i < numUpdates; i++ {
		newPoints := lo.Map(shares, func(s secretsharing.Share, _ int) *point {
			return &point{
				owner: id,
				val: secretsharing.Share{
					ID:    s.ID,
					Value: cointoss.NewScalar(1),
				},
			}
		})
		currBNode = addNode(uuid.New(), newPoints, []*backnode{currBNode})
	}
	fnode := makeSubgraph([]*backnode{currBNode})
	points := fnode.computeShareState()
	recovShares := lo.Map(points, func(p *point, _ int) secretsharing.Share {
		return p.val
	})
	assert.True(t, lo.EveryBy(recovShares, func(s secretsharing.Share) bool {
		return s.Value.IsEqual(cointoss.NewScalar(uint64(numUpdates)))
	}))
}

func TestShouldUpdateOwnersInLongChain(t *testing.T) {
	numIds := 100
	ids := lo.Map(lo.Range(numIds), func(_, _ int) uuid.UUID { return uuid.New() })
	shares := lo.Map(lo.Range(numIds), func(i, _ int) secretsharing.Share {
		return secretsharing.Share{
			ID:    cointoss.NewScalar(uint64(i)),
			Value: cointoss.NewScalar(0),
		}
	})
	currNode := initNode(shares, uuid.New(), ids[0])
	for i := 1; i < numIds-1; i++ {
		newPoints := lo.Map(shares, func(s secretsharing.Share, _ int) *point {
			return &point{
				owner: ids[0],
				val: secretsharing.Share{
					ID:    s.ID,
					Value: cointoss.NewScalar(0),
				},
			}
		})
		currNode = addNode(ids[i], newPoints, []*backnode{currNode})
	}
	newPoints := lo.Map(shares, func(s secretsharing.Share, i int) *point {
		return &point{
			owner: ids[i],
			val: secretsharing.Share{
				ID:    s.ID,
				Value: cointoss.NewScalar(0),
			},
		}
	})
	lastNode := addNode(ids[numIds-1], newPoints, []*backnode{currNode})
	fnode := makeSubgraph([]*backnode{lastNode})
	points := fnode.computeShareState()
	assert.Equal(t, len(ids), len(points))
	for _, tuple := range lo.Zip2(ids, points) {
		id, point := tuple.Unpack()
		assert.Equal(t, id, point.owner)
	}
}

func TestShouldUpdateValsInFork(t *testing.T) {
	numShares := 100
	shares := lo.Map(lo.Range(numShares), func(i, _ int) secretsharing.Share {
		return secretsharing.Share{
			ID:    cointoss.NewScalar(uint64(i)),
			Value: cointoss.NewScalar(0),
		}
	})
	firstNode := initNode(shares, uuid.New(), uuid.New())
	upNode := addNode(uuid.New(), lo.Map(shares, func(s secretsharing.Share, i int) *point {
		var val group.Scalar
		if i < numShares/2 {
			val = cointoss.NewScalar(1)
		} else {
			val = cointoss.NewScalar(0)
		}
		return &point{
			owner: firstNode.id,
			val: secretsharing.Share{
				ID:    s.ID,
				Value: val,
			},
		}
	}), []*backnode{firstNode})
	downNode := addNode(uuid.New(), lo.Map(shares, func(s secretsharing.Share, i int) *point {
		var val group.Scalar
		if i < numShares/2 {
			val = cointoss.NewScalar(0)
		} else {
			val = cointoss.NewScalar(2)
		}
		return &point{
			owner: firstNode.id,
			val: secretsharing.Share{
				ID:    s.ID,
				Value: val,
			},
		}
	}), []*backnode{firstNode})
	fnode := makeSubgraph([]*backnode{upNode, downNode})
	points := fnode.computeShareState()
	recovVals := lo.Map(points, func(p *point, _ int) group.Scalar { return p.val.Value })
	assert.Equal(t, numShares, len(points))
	for i, v := range recovVals {
		if i < numShares/2 {
			assert.True(t, v.IsEqual(cointoss.NewScalar(1)))
		} else {
			assert.True(t, v.IsEqual(cointoss.NewScalar(2)))
		}
	}
}

func TestShouldUpdateOwnersInFork(t *testing.T) {
	numShares := 100
	initialId := uuid.New()
	upId := uuid.New()
	downId := uuid.New()
	shares := lo.Map(lo.Range(numShares), func(i, _ int) secretsharing.Share {
		return secretsharing.Share{
			ID:    cointoss.NewScalar(uint64(i)),
			Value: cointoss.NewScalar(0),
		}
	})
	firstNode := initNode(shares, uuid.New(), initialId)
	upNode := addNode(uuid.New(), lo.Map(shares, func(s secretsharing.Share, i int) *point {
		owner := initialId
		if i >= numShares/3 && i < 2*numShares/3 {
			owner = upId
		}
		return &point{
			owner: owner,
			val: secretsharing.Share{
				ID:    s.ID,
				Value: cointoss.NewScalar(0),
			},
		}
	}), []*backnode{firstNode})
	downNode := addNode(uuid.New(), lo.Map(shares, func(s secretsharing.Share, i int) *point {
		owner := initialId
		if i >= 2*numShares/3 {
			owner = downId
		}
		return &point{
			owner: owner,
			val: secretsharing.Share{
				ID:    s.ID,
				Value: cointoss.NewScalar(0),
			},
		}
	}), []*backnode{firstNode})
	fnode := makeSubgraph([]*backnode{upNode, downNode})
	points := fnode.computeShareState()
	owners := lo.Map(points, func(p *point, _ int) uuid.UUID { return p.owner })
	for i, owner := range owners {
		if i < numShares/3 {
			assert.Equal(t, initialId, owner)
		} else if i < 2*numShares/3 {
			assert.Equal(t, upId, owner)
		} else {
			assert.Equal(t, downId, owner)
		}
	}
}
