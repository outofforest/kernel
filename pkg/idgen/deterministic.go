package idgen

import (
	"crypto/sha256"
	"encoding/binary"
)

type deterministicGenerator struct {
	key string
	seq uint64
}

// NewDeterministic creates new deterministic ID generator.
// Generators with the same key will produce exactly the same identifier sequences.
func NewDeterministic(key string) Generator {
	return &deterministicGenerator{key: key}
}

func (ds *deterministicGenerator) ID() string {
	h := sha256.New()
	// hash does not return errors or short writes
	_, _ = h.Write([]byte(ds.key))
	_ = binary.Write(h, binary.LittleEndian, ds.seq)
	ds.seq++
	return encodeID(h.Sum(nil))
}
