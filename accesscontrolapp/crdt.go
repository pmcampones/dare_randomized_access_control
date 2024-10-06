package accesscontrolapp

import (
	"dare_randomized_access_control/utils"
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
}

type InitOp struct {
	initial UUID
	points  uint32
}

type PostOp struct {
	poster UUID
	msg    string
}

type AddOp struct {
	issuer UUID
	added  UUID
	points uint32
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

func (crdt CRDT) Init(firstParticipant UUID, points uint32) func(depth int) error {
	init := &InitOp{
		initial: firstParticipant,
		points:  points,
	}
	op := &Op{
		idx:     0,
		kind:    Init,
		content: init,
	}
	return func(_ int) error {
		if crdt.tree.ReplaceOrInsert(op) != nil {
			return fmt.Errorf("init operation had already been issued")
		}
		return nil
	}
}

func (crdt CRDT) Post(poster UUID, msg string) func(depth int) error {
	post := &PostOp{
		poster: poster,
		msg:    msg,
	}
	return func(depth int) error {
		idx, err := crdt.computePostIdx(depth, poster, msg)
		if err != nil {
			return fmt.Errorf("unable to compute operation index: %v", err)
		}
		op := &Op{
			idx:     idx,
			kind:    Post,
			content: post,
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
	offset := utils.HashToInt(offsetInput)
	idx += int64(offset)
	return idx, nil
}

func (crdt CRDT) Add(issuer, added UUID, points uint32) func(depth int) error {
	add := &AddOp{
		issuer: issuer,
		added:  added,
		points: points,
	}
	return func(depth int) error {
		idx, err := crdt.computeAddIdx(depth, issuer, added)
		if err != nil {
			return fmt.Errorf("unable to compute operation index: %v", err)
		}
		op := &Op{
			idx:     idx,
			kind:    Add,
			content: add,
		}
		if crdt.tree.ReplaceOrInsert(op) != nil {
			return fmt.Errorf("another operation had the same idx")
		}
		return nil
	}
}

func (crdt CRDT) computeAddIdx(depth int, issuer UUID, added UUID) (int64, error) {
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
	offsetInput := append(issuerBytes, addedBytes...)
	offset := utils.HashToInt(offsetInput)
	idx += int64(offset)
	return idx, nil
}

func (crdt CRDT) Rem(issuer, removed UUID) func(depth int) error {
	rem := &RemOp{
		issuer:  issuer,
		removed: removed,
	}
	return func(depth int) error {
		idx, err := crdt.computeRemIdx(depth, issuer, removed)
		if err != nil {
			return fmt.Errorf("unable to compute operation index: %v", err)
		}
		op := &Op{
			idx:     idx,
			kind:    Rem,
			content: rem,
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
	offset := (utils.HashToInt(offsetInput) / 4) * 4
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
