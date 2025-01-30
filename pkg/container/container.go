package container

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/outofforest/cloudless/pkg/container/cache"
	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/retry"
	"github.com/outofforest/parallel"
)

const containerRoot = "/tmp/containers"

// Config represents container configuration.
type Config struct {
}

// Configurator defines function setting the container configuration.
type Configurator func(config *Config)

// New creates container.
func New(name, imageTag string, configurators ...Configurator) host.Configurator {
	return func(c *host.Configuration) error {
		var config Config

		for _, configurator := range configurators {
			configurator(&config)
		}

		c.RequireContainers(imageTag)
		c.StartServices(host.ServiceConfig{
			Name:   "container-" + name,
			OnExit: parallel.Continue,
			TaskFn: func(ctx context.Context) error {
				return inflateImage(ctx, name, imageTag, c.ContainerMirrors())
			},
		})

		return nil
	}
}

func inflateImage(ctx context.Context, name, imageTag string, mirrors []string) error {
	mirror := mirrors[0]
	manifestFile, err := cache.ManifestFile(imageTag)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mirror+"/"+manifestFile, nil)
	if err != nil {
		return errors.WithStack(err)
	}

	var m cache.Manifest
	if err := retry.Do(ctx, retry.FixedConfig{RetryAfter: 5 * time.Second, MaxAttempts: 10}, func() error {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return retry.Retriable(errors.WithStack(err))
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return retry.Retriable(errors.Errorf("unexpected status code %d", resp.StatusCode))
		}

		if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
			return retry.Retriable(errors.WithStack(err))
		}

		return nil
	}); err != nil {
		return err
	}

	for _, layer := range m.Layers {
		blobFile, err := cache.BlobFile(imageTag, layer.Digest)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, mirror+"/"+blobFile, nil)
		if err != nil {
			return errors.WithStack(err)
		}

		if err := retry.Do(ctx, retry.FixedConfig{RetryAfter: 5 * time.Second, MaxAttempts: 10}, func() error {
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return retry.Retriable(errors.WithStack(err))
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return retry.Retriable(errors.Errorf("unexpected status code %d", resp.StatusCode))
			}

			return inflateBlob(resp.Body, filepath.Join(containerRoot, name))
		}); err != nil {
			return err
		}
	}

	return nil
}

//nolint:gocyclo
func inflateBlob(r io.Reader, path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}

	gr, err := gzip.NewReader(r)
	if err != nil {
		return errors.WithStack(err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	del := map[string]bool{}
	added := map[string]bool{}
loop:
	for {
		header, err := tr.Next()
		switch {
		case err == io.EOF:
			break loop
		case err != nil:
			return retry.Retriable(err)
		case header == nil:
			continue
		}
		// We take mode from header.FileInfo().Mode(), not from header.Mode because they may be in different formats
		// (meaning of bits may be different). header.FileInfo().Mode() returns compatible value.
		mode := header.FileInfo().Mode()
		header.Name = filepath.Clean(filepath.Join(path, header.Name))
		if !strings.HasPrefix(header.Name, path+"/") {
			// It means image tries to create files outside its root. We don't like it.
			return errors.Errorf("image tries to create files outside its root: %q", header.Name)
		}
		if header.Linkname != "" {
			linkName := filepath.Clean(filepath.Join(path, header.Linkname))
			if !strings.HasPrefix(linkName, path+"/") {
				// It means image tries to link to files outside its root. We don't like it.
				// We don't return error because for some reason images try to do this.
				continue loop
			}
		}

		switch {
		case filepath.Base(header.Name) == ".wh..wh..plnk":
			// just ignore this
			continue
		case filepath.Base(header.Name) == ".wh..wh..opq":
			// It means that content in this directory created by earlier layers should not be visible,
			// so content created earlier must be deleted.
			dir := filepath.Dir(header.Name)
			files, err := os.ReadDir(dir)
			if err != nil {
				return errors.WithStack(err)
			}
			for _, f := range files {
				toDelete := filepath.Join(dir, f.Name())
				if added[toDelete] {
					continue
				}
				if err := os.RemoveAll(toDelete); err != nil {
					return errors.WithStack(err)
				}
			}
			continue
		case strings.HasPrefix(filepath.Base(header.Name), ".wh."):
			// delete or mark to delete corresponding file
			toDelete := filepath.Join(filepath.Dir(header.Name), strings.TrimPrefix(filepath.Base(header.Name), ".wh."))
			delete(added, toDelete)
			if err := os.RemoveAll(toDelete); err != nil {
				if os.IsNotExist(err) {
					del[toDelete] = true
					continue
				}
				return errors.WithStack(err)
			}
			continue
		case del[header.Name]:
			delete(del, header.Name)
			delete(added, header.Name)
			continue
		case header.Typeflag == tar.TypeDir:
			if err := os.MkdirAll(header.Name, mode); err != nil {
				return errors.WithStack(err)
			}
		case header.Typeflag == tar.TypeReg:
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
			if err := os.Symlink(header.Linkname, header.Name); err != nil {
				return errors.WithStack(err)
			}
		case header.Typeflag == tar.TypeLink:
			header.Linkname = filepath.Clean(filepath.Join(path, header.Linkname))
			// linked file may not exist yet, so let's create it - it will be overwritten later
			if err := os.MkdirAll(filepath.Dir(header.Linkname), 0o700); err != nil {
				return errors.WithStack(err)
			}
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

		added[header.Name] = true
		if err := os.Lchown(header.Name, header.Uid, header.Gid); err != nil {
			return errors.WithStack(err)
		}

		// Unless CAP_FSETID capability is set for the process every operation modifying the file/dir will reset
		// setuid, setgid nd sticky bits. After saving those files/dirs the mode has to be set once again to set those
		// bits. This has to be the last operation on the file/dir.
		// On linux mode is not supported for symlinks, mode is always taken from target location.
		if header.Typeflag != tar.TypeSymlink {
			if err := os.Chmod(header.Name, mode); err != nil {
				return errors.WithStack(err)
			}
		}
	}
	return nil
}
