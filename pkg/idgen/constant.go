package idgen

import (
	"regexp"

	"github.com/pkg/errors"
)

var idRegex = regexp.MustCompile("^[" + zBase32Alphabet + "]{26}$")

// NewConstant returns new generator that produces a constant ID once.
func NewConstant(id string) Generator {
	if !idRegex.MatchString(id) {
		panic(errors.Errorf("expected 128 bits encoded to z-base-32, got %s", id))
	}
	return &constantGenerator{id: &id}
}

// constantGenerator is a generator.
type constantGenerator struct {
	id *string
}

// ID is the implementation of Generator.ID.
func (cg *constantGenerator) ID() string {
	if cg.id == nil {
		// id was discarded, constantGenerator.ID shouldn't be use more than once
		panic("constantGenerator.ID shouldn't be use more than once")
	}
	id := *cg.id
	cg.id = nil
	return id
}
