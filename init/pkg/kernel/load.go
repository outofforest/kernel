package kernel

import (
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
)

const basePath = "/usr/lib/modules"

// LoadModule loads kernel module.
func LoadModule(path string) error {
	release, err := Release()
	if err != nil {
		return err
	}

	f, err := os.Open(filepath.Join(basePath, release, path))
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	r, err := xz.NewReader(f)
	if err != nil {
		return errors.WithStack(err)
	}

	mod, err := io.ReadAll(r)
	if err != nil {
		return errors.WithStack(err)
	}

	return errors.WithStack(unix.InitModule(mod, ""))
}
