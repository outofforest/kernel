// Package idgen produces identifiers.
//
// These identifiers have the following properties:
//   - unique (~128 bit of randomness)
//   - usable as DNS label (strict RFC1035, no digits in first position)
//   - reasonably easy for humans to manipulate
//     (see http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt)
//   - reasonably short (26 characters)
package idgen
