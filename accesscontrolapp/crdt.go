package accesscontrolapp

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	. "github.com/google/uuid"
	"github.com/petar/GoLLRB/llrb"
	"unsafe"
)

const u32Bits = int(unsafe.Sizeof(uint32(0))) * 8
const opOffsetSize = 2

type OpType byte

const (
	Init OpType = iota
	Post
	Add
	Rem
)

type OpOffset int

const (
	RemOffset OpOffset = iota
	AddOffset
	PostOffset
)

type Op struct {
	idx     int64
	kind    OpType
	content interface{}
	id      UUID
	prevIds []UUID
}

type InitOp struct {
	initial    UUID
	prettyName string
}

type PostOp struct {
	poster UUID
	msg    string
}

type AddOp struct {
	issuer     UUID
	added      UUID
	points     []uint
	prettyName string
}

type RemOp struct {
	issuer  UUID
	removed UUID
}

type ConflictResolutionOp struct {
	val float64
}

func (op *Op) Less(other llrb.Item) bool {
	otherOp := other.(*Op)
	return op.idx < otherOp.idx
}

type CRDT struct {
	tree *llrb.LLRB
}

func NewCRDT() CRDT {
	return CRDT{tree: llrb.New()}
}

func (crdt CRDT) Init(firstParticipant UUID, prettyName string) func(depth int, id UUID, prevIds []UUID) error {
	init := &InitOp{
		initial:    firstParticipant,
		prettyName: prettyName,
	}
	op := &Op{
		idx:     0,
		kind:    Init,
		content: init,
		prevIds: []UUID{},
	}
	return func(_ int, id UUID, _ []UUID) error {
		op.id = id
		if crdt.tree.ReplaceOrInsert(op) != nil {
			return fmt.Errorf("init operation had already been issued")
		}
		return nil
	}
}

func (crdt CRDT) Post(poster UUID, msg string) func(depth int, id UUID, prevIds []UUID) error {
	post := &PostOp{
		poster: poster,
		msg:    msg,
	}
	return func(depth int, id UUID, prevIds []UUID) error {
		idx, err := crdt.computePostIdx(depth, poster, msg)
		if err != nil {
			return fmt.Errorf("unable to compute operation index: %v", err)
		}
		op := &Op{
			idx:     idx,
			kind:    Post,
			content: post,
			id:      id,
			prevIds: prevIds,
		}
		if crdt.tree.ReplaceOrInsert(op) != nil {
			return fmt.Errorf("another operation had the same idx")
		}
		return nil
	}
}

func (crdt CRDT) computePostIdx(depth int, poster UUID, msg string) (int64, error) {
	var idx int64
	idx = int64(depth << (u32Bits + opOffsetSize))
	idx += int64(int(PostOffset) << u32Bits)
	idBytes, err := poster.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("unable to marshal id of the message poster: %v", err)
	}
	msgBytes := []byte(msg)
	offsetInput := append(idBytes, msgBytes...)
	offset := hashToInt(offsetInput)
	idx += int64(offset)
	return idx, nil
}

func (crdt CRDT) Add(issuer, added UUID, prettyName string, points []uint) func(depth int, id UUID, prevIds []UUID) error {
	add := &AddOp{
		issuer:     issuer,
		added:      added,
		points:     points,
		prettyName: prettyName,
	}
	return func(depth int, id UUID, prevIds []UUID) error {
		idx, err := crdt.computeAddIdx(depth, issuer, added, points)
		if err != nil {
			return fmt.Errorf("unable to compute operation index: %v", err)
		}
		op := &Op{
			idx:     idx,
			kind:    Add,
			content: add,
			id:      id,
			prevIds: prevIds,
		}
		if crdt.tree.ReplaceOrInsert(op) != nil {
			return fmt.Errorf("another operation had the same idx")
		}
		return nil
	}
}

func (crdt CRDT) computeAddIdx(depth int, issuer UUID, added UUID, points []uint) (int64, error) {
	var idx int64
	idx = int64(depth << (u32Bits + opOffsetSize))
	idx += int64(int(AddOffset) << u32Bits)
	issuerBytes, err := issuer.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("unable to marshal issuer: %v", err)
	}
	addedBytes, err := added.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("unable to marshal added user: %v", err)
	}
	pointBytes := make([]byte, unsafe.Sizeof(points))
	binary.LittleEndian.PutUint32(pointBytes, uint32(len(points)))
	offsetInput := append(append(issuerBytes, addedBytes...), pointBytes...)
	offset := hashToInt(offsetInput)
	idx += int64(offset)
	return idx, nil
}

func (crdt CRDT) Rem(issuer, removed UUID) func(depth int, id UUID, prevIds []UUID) error {
	rem := &RemOp{
		issuer:  issuer,
		removed: removed,
	}
	return func(depth int, id UUID, prevIds []UUID) error {
		idx, err := crdt.computeRemIdx(depth, issuer, removed)
		if err != nil {
			return fmt.Errorf("unable to compute operation index: %v", err)
		}
		op := &Op{
			idx:     idx,
			kind:    Rem,
			content: rem,
			id:      id,
			prevIds: prevIds,
		}
		if crdt.tree.ReplaceOrInsert(op) != nil {
			return fmt.Errorf("another operation had the same idx")
		}
		return nil
	}
}

func (crdt CRDT) computeRemIdx(depth int, issuer UUID, removed UUID) (int64, error) {
	var idx int64
	idx = int64(depth << (u32Bits + opOffsetSize))
	idx += int64(int(RemOffset) << u32Bits)
	issuerBytes, err := issuer.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("unable to marshal issuer: %v", err)
	}
	remBytes, err := removed.MarshalBinary()
	if err != nil {
		return 0, fmt.Errorf("unable to marshal removed user: %v", err)
	}
	var first, last []byte
	var order int64
	isFirstLower := issuer.String() < removed.String()
	if isFirstLower {
		first = issuerBytes
		last = remBytes
		order = 0
	} else {
		first = remBytes
		last = issuerBytes
		order = 1
	}
	offsetInput := append(first, last...)
	offset := (hashToInt(offsetInput) / 4) * 4
	idx += int64(offset)
	idx += order
	return idx, nil
}

func (crdt CRDT) GetOperationList() []*Op {
	result := make([]*Op, 0, crdt.tree.Len())
	smallestOp := &Op{idx: -1}
	crdt.tree.AscendGreaterOrEqual(smallestOp, func(i llrb.Item) bool {
		result = append(result, i.(*Op))
		return true
	})
	return result
}

func hashToInt(b []byte) uint32 {
	hashVal := sha256.Sum256(b)
	return binary.BigEndian.Uint32(hashVal[:unsafe.Sizeof(uint32(0))])
}
