package accesscontrolapp

import (
	"crypto/sha256"
	_ "crypto/sha256"
	"dare_randomized_access_control/cointoss"
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
	"github.com/google/uuid"
	"github.com/negrel/assert"
	"github.com/petar/GoLLRB/llrb"
	"github.com/samber/lo"
	"log/slog"
	"math/rand"
	"unsafe"
)

type Msg struct {
	Issuer  uuid.UUID
	Content string
}

type User struct {
	Id     uuid.UUID
	Points *llrb.LLRB
}

type pt struct {
	pt int
}

func (p *pt) Less(than llrb.Item) bool {
	return p.pt < than.(*pt).pt
}

type App struct {
	secret     secretsharing.Share
	numPoints  int
	threshold  int
	users      map[uuid.UUID]*User
	msgs       []Msg
	graphNodes map[uuid.UUID]*backnode
}

func ExecuteCRDT(crdt *CRDT, numPoints, threshold int) (*App, error) {
	app := NewApp(numPoints, threshold)
	opList := crdt.GetOperationList()
	i := 0
	for i < len(opList) {
		op := opList[i]
		switch op.kind {
		case Init:
			err := execInit(op, app)
			if err != nil {
				return app, err
			}
			i++
		case Add:
			err := execAdd(op, app)
			if err != nil {
				slog.Warn("Unable to compute add operation", "err", err, "idx", op.idx, "op", op.content.(*AddOp))
			}
			i++
		case Rem:
			if isConcurrent(opList, i) {
				err := execConcurrent(op, opList[i+1], op.idx, app)
				if err != nil {
					slog.Warn("Unable to compute concurrent removal operation", "err", err, "idx", op.idx, "op", op.content.(*RemOp))
					i++
				} else {
					i += 2
				}
			} else {
				err := execRem(op, app)
				if err != nil {
					slog.Warn("Unable to compute removal operation", "err", err, "idx", op.idx, "op", op.content.(*RemOp))
				}
				i++
			}
		case Post:
			err := execPost(op, app)
			if err != nil {
				slog.Warn("Unable to compute post operation", "err", err, "idx", op.idx, "op", op.content.(*PostOp))
			}
			i++
		default:
			return app, fmt.Errorf("unhandled operation type")
		}
	}
	return app, nil
}

func NewApp(numPoints, threshold int) *App {
	r := rand.New(rand.NewSource(int64(0)))
	share := secretsharing.Share{
		ID:    group.Ristretto255.NewScalar(),
		Value: group.Ristretto255.RandomScalar(r),
	}
	return &App{
		secret:     share,
		numPoints:  numPoints,
		threshold:  threshold,
		users:      make(map[uuid.UUID]*User),
		msgs:       make([]Msg, 0),
		graphNodes: make(map[uuid.UUID]*backnode),
	}
}

func execInit(op *Op, app *App) error {
	if len(app.users) != 0 {
		return fmt.Errorf("already initialized")
	}
	pts := llrb.New()
	init := op.content.(*InitOp)
	for _, p := range lo.Range(app.numPoints) {
		pts.InsertNoReplace(&pt{pt: p})
	}
	points := lo.Map(lo.Range(app.numPoints), func(p int, _ int) uint { return uint(p) })
	user := newUser(init.initial, points)
	bnode := app.initialBacknode(op.id, init.initial, app.numPoints)
	app.graphNodes[bnode.id] = bnode
	app.users[init.initial] = user
	return nil
}

func execAdd(op *Op, app *App) error {
	add := op.content.(*AddOp)
	if canAdd, reason := app.canAdd(op); !canAdd {
		return fmt.Errorf(reason)
	}
	issuer := app.users[add.issuer]
	for _, p := range add.points {
		issuer.Points.Delete(&pt{pt: int(p)})
	}
	added := newUser(add.added, add.points)
	app.users[add.added] = added
	app.graphNodes[op.id] = addBnode(op, app, add)
	return nil
}

func addBnode(op *Op, app *App, add *AddOp) *backnode {
	ot := lo.Map(add.points, func(p uint, _ int) *ownerTransfer { return &ownerTransfer{shareIdx: p, owner: add.added} })
	prev := lo.Map(op.prevIds, func(id uuid.UUID, _ int) *backnode { return app.graphNodes[id] })
	bnode := &backnode{
		id:             op.id,
		deltaVals:      cointoss.ShareRandomSecret(uint(app.threshold), uint(app.numPoints)),
		ownerTransfers: ot,
		prev:           prev,
	}
	return bnode
}

func (app *App) canAdd(op *Op) (bool, string) {
	if !app.hasPrevious(op) {
		return false, "previous operation ids do not exist"
	}
	add := op.content.(*AddOp)
	if add.issuer == add.added {
		return false, "user cannot add themselves"
	} else if len(add.points) == 0 {
		return false, "at least a single point must be given"
	}
	issuer := app.users[add.issuer]
	if issuer == nil {
		return false, "operation issuer is not a user"
	} else if len(add.points) >= issuer.Points.Len() {
		return false, "issuer cannot give more or equal points than what they have"
	} else if !lo.EveryBy(add.points, func(p uint) bool { return issuer.Points.Has(&pt{pt: int(p)}) }) {
		return false, "issuer cannot give points they do not have"
	}
	if app.users[add.added] != nil {
		return false, "added user already exists"
	}
	return true, ""
}

func execPost(op *Op, app *App) error {
	post := op.content.(*PostOp)
	poster := app.users[post.poster]
	if !app.hasPrevious(op) {
		return fmt.Errorf("previous operation ids do not exist")
	} else if poster == nil {
		return fmt.Errorf("operation poster is not a user")
	}
	msg := Msg{
		Issuer:  post.poster,
		Content: post.msg,
	}
	app.msgs = append(app.msgs, msg)
	app.graphNodes[op.id] = postBNode(op, app)
	return nil
}

func postBNode(op *Op, app *App) *backnode {
	prev := lo.Map(op.prevIds, func(id uuid.UUID, _ int) *backnode { return app.graphNodes[id] })
	bnode := &backnode{
		id:             op.id,
		deltaVals:      []secretsharing.Share{},
		ownerTransfers: []*ownerTransfer{},
		prev:           prev,
	}
	return bnode
}

func isConcurrent(opList []*Op, i int) bool {
	assert.Equal(Rem, opList[i].kind, "First operation must be removal when this method is called")
	if (i+1) >= len(opList) || opList[i+1].kind != Rem {
		return false
	}
	rem1 := opList[i].content.(*RemOp)
	rem2 := opList[i+1].content.(*RemOp)
	return rem1.issuer == rem2.removed && rem1.removed == rem2.issuer
}

func execConcurrent(op1, op2 *Op, seed int64, app *App) error {
	canRem, reason := app.canRemUser(op1)
	if !canRem {
		return fmt.Errorf(reason)
	}
	coin, err := computeCoinToss(seed, app.secret)
	if err != nil {
		return fmt.Errorf("unable to compute coin toss: %v", err)
	}
	threshold := app.computeThreshold(op1)
	if coin < threshold {
		if err = execRem(op1, app); err != nil {
			return err
		}
		app.graphNodes[op2.id] = dummyBNode(op2, app)
	} else {
		if err = execRem(op2, app); err != nil {
			return err
		}
		app.graphNodes[op1.id] = dummyBNode(op1, app)
	}
	return nil
}

func dummyBNode(op *Op, app *App) *backnode {
	prev := lo.Map(op.prevIds, func(id uuid.UUID, _ int) *backnode { return app.graphNodes[id] })
	return &backnode{
		id:             op.id,
		deltaVals:      []secretsharing.Share{},
		ownerTransfers: []*ownerTransfer{},
		prev:           prev,
	}
}

func execRem(op *Op, app *App) error {
	rem := op.content.(*RemOp)
	canRem, reason := app.canRemUser(op)
	if !canRem {
		return fmt.Errorf(reason)
	}
	issuer := app.users[rem.issuer]
	removed := app.users[rem.removed]
	assert.True(areSetsDisjoint(issuer.Points, removed.Points), "points must be disjoint")
	transferPoints(removed.Points, issuer.Points)
	app.graphNodes[op.id] = remBNode(op, app)
	delete(app.users, rem.removed)
	return nil
}

func remBNode(op *Op, app *App) *backnode {
	prev := lo.Map(op.prevIds, func(id uuid.UUID, _ int) *backnode { return app.graphNodes[id] })
	rem := op.content.(*RemOp)
	ot := make([]*ownerTransfer, 0)
	removed := app.users[rem.removed]
	removed.Points.AscendGreaterOrEqual(removed.Points.Min(), func(val llrb.Item) bool {
		ot = append(ot, &ownerTransfer{shareIdx: uint(val.(*pt).pt), owner: rem.issuer})
		return true
	})
	return &backnode{
		id:             op.id,
		deltaVals:      cointoss.ShareRandomSecret(uint(app.threshold), uint(app.numPoints)),
		ownerTransfers: ot,
		prev:           prev,
	}
}

func (app *App) initialBacknode(id, owner uuid.UUID, points int) *backnode {
	shares := cointoss.ShareRandomSecret(uint(app.threshold), uint(points))
	ot := lo.Map(shares, func(_ secretsharing.Share, i int) *ownerTransfer {
		return &ownerTransfer{shareIdx: uint(i), owner: owner}
	})
	return &backnode{
		id:             id,
		deltaVals:      shares,
		ownerTransfers: ot,
		prev:           []*backnode{},
	}
}

func (app *App) computeThreshold(op *Op) float64 {
	rem := op.content.(*RemOp)
	issuer := app.users[rem.issuer]
	removed := app.users[rem.removed]
	issuerPoints := issuer.Points.Len()
	totalPoints := issuerPoints + removed.Points.Len()
	threshold := float64(issuerPoints) / float64(totalPoints)
	return threshold
}

func computeCoinToss(seed int64, secret secretsharing.Share) (float64, error) {
	seedBytes := make([]byte, unsafe.Sizeof(seed))
	binary.LittleEndian.PutUint64(seedBytes, uint64(seed))
	hash := sha256.Sum256(seedBytes)
	base := group.Ristretto255.HashToElement(hash[:], []byte("concurrent_rem_base"))
	point := cointoss.ShareToPoint(secret, base)
	coin, err := cointoss.HashPointToDouble(point.Point)
	if err != nil {
		return 0, fmt.Errorf("unable to hash secret point to number: %v", err)
	}
	return coin, nil
}

func transferPoints(from, to *llrb.LLRB) {
	from.AscendGreaterOrEqual(from.Min(), func(val llrb.Item) bool {
		to.InsertNoReplace(val)
		return true
	})
}

func areSetsDisjoint(a, b *llrb.LLRB) bool {
	disjoint := true
	a.AscendGreaterOrEqual(a.Min(), func(val llrb.Item) bool {
		if b.Has(val) {
			disjoint = false
			return false
		}
		return true
	})
	return disjoint
}

func (app *App) canRemUser(op *Op) (bool, string) {

	rem := op.content.(*RemOp)
	if rem.issuer == rem.removed {
		return false, "user cannot remove themselves"
	}
	issuer := app.users[rem.issuer]
	removed := app.users[rem.removed]
	if issuer == nil {
		return false, "operation issuer is not a user"
	} else if removed == nil {
		return false, "removed user is not in the system"
	}
	return true, ""
}

func newUser(id uuid.UUID, points []uint) *User {
	pts := llrb.New()
	for _, p := range points {
		pts.InsertNoReplace(&pt{pt: int(p)})
	}
	return &User{
		Id:     id,
		Points: pts,
	}
}

func (app *App) hasPrevious(op *Op) bool {
	return lo.EveryBy(op.prevIds, func(prev uuid.UUID) bool { return app.graphNodes[prev] != nil })
}
