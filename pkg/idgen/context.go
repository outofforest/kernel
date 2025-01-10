package idgen

import "context"

type generatorKeyType int

const generatorKey generatorKeyType = iota

// WithGenerator returns a cloned context.Context with the given Generator
// injected into it.
func WithGenerator(ctx context.Context, generator Generator) context.Context {
	return context.WithValue(ctx, generatorKey, generator)
}

// FromContext returns the Generator that WithGenerator has injected into the
// context.
func FromContext(ctx context.Context) Generator {
	return ctx.Value(generatorKey).(Generator)
}

// ID generates an ID using the generator from the given context.
func ID(ctx context.Context) string {
	return FromContext(ctx).ID()
}
