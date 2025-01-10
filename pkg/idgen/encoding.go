package idgen

import (
	"encoding/base32"
	"fmt"
	"regexp"
)

const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

var zBase32Encoding = base32.NewEncoding(zBase32Alphabet).WithPadding(base32.NoPadding)

const idBytes = 16

func encodeID(data []byte) string {
	return zBase32Encoding.EncodeToString(data[:idBytes])
}

func divCeil(a, b int) int {
	return (a + b - 1) / b
}

// RE is a (fragment of) a regular expression that matches a possible ID.
var RE = regexp.MustCompile(fmt.Sprintf("[%s]{%d}", zBase32Alphabet, divCeil(idBytes*8, 5)))
