package cointoss

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/circl/group"
	"github.com/cloudflare/circl/secretsharing"
	"github.com/samber/lo"
	"math"
	"unsafe"
)

// PointShare is a secret share hidden in a group operation.
// This is used in the coin tossing scheme to hide the secret while making it usable as a randomness source.
type PointShare struct {
	id    group.Scalar
	Point group.Element
}

func ShareRandomSecret(threshold uint, nodes uint) []secretsharing.Share {
	return ShareSecret(threshold, nodes, group.Ristretto255.RandomScalar(rand.Reader))
}

func ShareSecret(threshold uint, nodes uint, secret group.Scalar) []secretsharing.Share {
	secretSharing := secretsharing.New(rand.Reader, threshold, secret)
	return secretSharing.Share(nodes)
}

func RecoverSecret(threshold uint, shares []secretsharing.Share) (group.Scalar, error) {
	return secretsharing.Recover(threshold, shares)
}

func ShareToPoint(share secretsharing.Share, base group.Element) PointShare {
	return PointShare{
		id:    share.ID,
		Point: mulPoint(base, share.Value),
	}
}

func RecoverSecretFromPoints(shares []PointShare) group.Element {
	indices := lo.Map(shares, func(share PointShare, _ int) group.Scalar { return share.id })
	coefficients := lo.Map(indices, func(i group.Scalar, _ int) group.Scalar { return lagrangeCoefficient(i, indices) })
	terms := lo.ZipBy2(shares, coefficients, func(share PointShare, coeff group.Scalar) group.Element {
		return mulPoint(share.Point, coeff)
	})
	return lo.Reduce(terms[1:], func(acc group.Element, term group.Element, _ int) group.Element {
		return addPoint(acc, term)
	}, terms[0])
}

func lagrangeCoefficient(i group.Scalar, indices []group.Scalar) group.Scalar {
	filteredIndices := lo.Filter(indices, func(j group.Scalar, _ int) bool { return !i.IsEqual(j) })
	numerators := lo.Reduce(filteredIndices, func(acc group.Scalar, j group.Scalar, _ int) group.Scalar {
		return mulScalar(neg(j), acc)
	}, NewScalar(uint64(1)))
	denominators := lo.Reduce(filteredIndices, func(acc group.Scalar, j group.Scalar, _ int) group.Scalar {
		return mulScalar(acc, sub(i, j))
	}, NewScalar(uint64(1)))
	return mulScalar(numerators, inv(denominators))
}

func HashPointToDouble(point group.Element) (float64, error) {
	pointMarshal, err := point.MarshalBinary()
	if err != nil {
		return -1, fmt.Errorf("unable to generate bytes from Point: %v", err)
	}
	hashed := sha256.Sum256(pointMarshal)
	val := binary.LittleEndian.Uint64(hashed[:unsafe.Sizeof(uint64(0))])
	return float64(val / math.MaxUint64), err
}
