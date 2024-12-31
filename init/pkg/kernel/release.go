package kernel

import (
	"syscall"

	"github.com/pkg/errors"
)

// Release returns kernel release.
func Release() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", errors.WithStack(err)
	}

	b := make([]byte, 0, len(uname.Release))
	for _, c := range uname.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b), nil
}
