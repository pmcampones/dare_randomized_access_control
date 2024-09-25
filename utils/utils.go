package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	. "github.com/google/uuid"
	"unsafe"
)

func HashToInt(b []byte) uint32 {
	hashVal := sha256.Sum256(b)
	return binary.BigEndian.Uint32(hashVal[:unsafe.Sizeof(uint32(0))])
}

func BytesToUUID(b []byte) UUID {
	hashVal := sha256.Sum256(b)
	return UUID(hashVal[:])
}

func ExtractIdFromMessage(reader *bytes.Reader) (UUID, error) {
	idLen := unsafe.Sizeof(UUID{})
	idBytes := make([]byte, idLen)
	num, err := reader.Read(idBytes)
	if err != nil {
		return Nil, fmt.Errorf("unable to read idBytes from message during instance idBytes computation: %v", err)
	} else if num != int(idLen) {
		return Nil, fmt.Errorf("unable to read idBytes from message during instance idBytes computation: read %d bytes, expected %d", num, idLen)
	}
	id, err := FromBytes(idBytes)
	if err != nil {
		return Nil, fmt.Errorf("unable to convert idBytes to UUID during instance idBytes computation: %v", err)
	}
	return id, nil
}
