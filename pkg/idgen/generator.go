package idgen

// Generator is a generator of unique identifiers.
type Generator interface {
	// ID generates a new unique identifier
	ID() string
}
