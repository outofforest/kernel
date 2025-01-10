package mount

import (
	"archive/tar"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

// ProcFS mounts procfs.
func ProcFS(dir string) error {
	if err := os.MkdirAll(dir, 0o555); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(syscall.Mount("none", dir, "proc", 0, ""))
}

// DevFS mounts devfs.
func DevFS(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(syscall.Mount("none", dir, "devtmpfs", 0, "size=4m"))
}

// DevPtsFS mounts devpts.
func DevPtsFS(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(syscall.Mount("none", dir, "devpts", 0, ""))
}

// SysFS mounts sysfs.
func SysFS(dir string) error {
	if err := os.MkdirAll(dir, 0o555); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(syscall.Mount("none", dir, "sysfs", 0, ""))
}

// TmpFS mounts tmpfs.
func TmpFS(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(syscall.Mount("none", dir, "tmpfs", 0, ""))
}

// Root mounts root filesystem.
// FIXME (wojciech): Remove init and initramfs.tar files.
func Root() error {
	if err := TmpFS("/newroot"); err != nil {
		return err
	}

	if err := os.Chdir("/newroot"); err != nil {
		return errors.WithStack(err)
	}

	if err := untarInitramfs(); err != nil {
		return err
	}

	if err := os.MkdirAll("/newroot/oldroot", 0o700); err != nil {
		return errors.WithStack(err)
	}
	if err := syscall.Mount("/", "/newroot/oldroot", "", syscall.MS_BIND, ""); err != nil {
		return errors.WithStack(err)
	}
	if err := syscall.Mount("/newroot", "/", "", syscall.MS_MOVE, ""); err != nil {
		return errors.WithStack(err)
	}
	if err := syscall.Chroot("."); err != nil {
		return errors.WithStack(err)
	}

	if err := ProcFS("/proc"); err != nil {
		return err
	}
	if err := SysFS("/sys"); err != nil {
		return err
	}
	if err := DevFS("/dev"); err != nil {
		return err
	}
	return DevPtsFS("/dev/pts")
}

func untarInitramfs() error {
	f, err := os.Open("/initramfs.tar")
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	return untar(f)
}

func untar(reader io.Reader) error {
	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return errors.WithStack(err)
		case header == nil:
			continue
		}

		// We take mode from header.FileInfo().Mode(), not from header.Mode because they may be in
		// different formats (meaning of bits may be different).
		// header.FileInfo().Mode() returns compatible value.
		mode := header.FileInfo().Mode()
		header.Name = strings.TrimPrefix(header.Name, "./")

		switch {
		case header.Name == "":
			continue
		case header.Typeflag == tar.TypeDir:
			if err := os.MkdirAll(header.Name, mode); err != nil {
				return errors.WithStack(err)
			}
		case header.Typeflag == tar.TypeReg:
			if err := ensureDir(header.Name); err != nil {
				return err
			}

			f, err := os.OpenFile(header.Name, os.O_CREATE|os.O_WRONLY, mode)
			if err != nil {
				return errors.WithStack(err)
			}
			_, err = io.Copy(f, tr)
			_ = f.Close()
			if err != nil {
				return errors.WithStack(err)
			}
		case header.Typeflag == tar.TypeSymlink:
			if err := ensureDir(header.Name); err != nil {
				return err
			}
			if err := os.Symlink(header.Linkname, header.Name); err != nil {
				return errors.WithStack(err)
			}
		case header.Typeflag == tar.TypeLink:
			header.Linkname = strings.TrimPrefix(header.Linkname, "./")
			if err := ensureDir(header.Name); err != nil {
				return err
			}
			if err := ensureDir(header.Linkname); err != nil {
				return err
			}
			// linked file may not exist yet, so let's create it - it will be overwritten later
			f, err := os.OpenFile(header.Linkname, os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				if !os.IsExist(err) {
					return errors.WithStack(err)
				}
			} else {
				_ = f.Close()
			}
			if err := os.Link(header.Linkname, header.Name); err != nil {
				return errors.WithStack(err)
			}
		default:
			return errors.Errorf("unsupported file type: %d", header.Typeflag)
		}
	}
}

func ensureDir(file string) error {
	return errors.WithStack(os.MkdirAll(filepath.Dir(file), 0o700))
}
