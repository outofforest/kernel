package container

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/outofforest/cloudless/cnet"
	"github.com/outofforest/cloudless/pkg/container/cache"
	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/cloudless/pkg/parse"
	"github.com/outofforest/cloudless/pkg/retry"
	"github.com/outofforest/parallel"
)

const containerRoot = "/tmp/containers"

// Config represents container configuration.
type Config struct {
	Name     string
	Networks []NetworkConfig
}

// NetworkConfig represents container's network configuration.
type NetworkConfig struct {
	Name string
	MAC  net.HardwareAddr
}

// Configurator defines function setting the container configuration.
type Configurator func(config *Config)

// RunImageConfig represents container image execution configuration.
type RunImageConfig struct {
}

// RunImageConfigurator defines function setting the container image execution configuration.
type RunImageConfigurator func(config *RunImageConfig)

// New creates container.
func New(name string, configurators ...Configurator) host.Configurator {
	return func(c *host.Configuration) error {
		config := Config{
			Name: name,
		}

		for _, configurator := range configurators {
			configurator(&config)
		}

		c.StartServices(host.ServiceConfig{
			Name:   "container-" + name,
			OnExit: parallel.Continue,
			TaskFn: func(ctx context.Context) error {
				cmd, err := command(config)
				if err != nil {
					return err
				}
				if err := cmd.Start(); err != nil {
					return errors.WithStack(err)
				}

				if err := joinNetworks(cmd.Process.Pid, config); err != nil {
					return err
				}

				if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
					return errors.WithStack(err)
				}

				return errors.WithStack(cmd.Wait())
			},
		})

		return nil
	}
}

// Network adds network to the config.
func Network(name, mac string) Configurator {
	return func(c *Config) {
		c.Networks = append(c.Networks, NetworkConfig{
			Name: name,
			MAC:  parse.MAC(mac),
		})
	}
}

// RunImage runs image.
func RunImage(imageTag string, configurators ...RunImageConfigurator) host.Configurator {
	return func(c *host.Configuration) error {
		c.RequireContainers(imageTag)
		c.StartServices(host.ServiceConfig{
			Name:   "image-" + imageTag,
			OnExit: parallel.Continue,
			TaskFn: func(ctx context.Context) error {
				if !c.IsContainer() {
					return errors.New("image must be run inside container")
				}

				var config RunImageConfig

				for _, configurator := range configurators {
					configurator(&config)
				}

				return inflateImage(ctx, imageTag, c.ContainerMirrors())
			},
		})

		return nil
	}
}

func command(config Config) (*exec.Cmd, error) {
	containerDir := filepath.Join(containerRoot, config.Name)
	if err := os.MkdirAll(containerDir, 0o700); err != nil {
		return nil, errors.WithStack(err)
	}

	cmd := exec.Command("/proc/self/exe")
	cmd.Dir = containerDir
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{host.ContainerEnvVar + "=" + config.Name}
	cmd.SysProcAttr = &unix.SysProcAttr{
		Pdeathsig: unix.SIGKILL,
		Cloneflags: unix.CLONE_NEWPID |
			unix.CLONE_NEWNS |
			unix.CLONE_NEWUSER |
			unix.CLONE_NEWIPC |
			unix.CLONE_NEWUTS |
			unix.CLONE_NEWCGROUP |
			unix.CLONE_NEWNET,
		AmbientCaps: []uintptr{
			unix.CAP_SYS_ADMIN, // by adding CAP_SYS_ADMIN executor may mount /proc
		},
		UidMappings: []syscall.SysProcIDMap{
			{
				HostID:      0,
				ContainerID: 0,
				Size:        65535,
			},
		},
		GidMappingsEnableSetgroups: true,
		GidMappings: []syscall.SysProcIDMap{
			{
				HostID:      0,
				ContainerID: 0,
				Size:        65535,
			},
		},
	}

	return cmd, nil
}

func joinNetworks(pid int, config Config) error {
	for _, n := range config.Networks {
		link, err := netlink.LinkByName(cnet.BridgeName(n.Name))
		if err != nil {
			return errors.WithStack(err)
		}
		bridgeLink, ok := link.(*netlink.Bridge)
		if !ok {
			return errors.New("link is not a bridge")
		}

		name := vethName(config.Name, n.Name)
		hostVETHName := name + "0"
		containerVETHName := name + "1"

		vethHost := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name: hostVETHName,
			},
			PeerName:         containerVETHName,
			PeerHardwareAddr: n.MAC,
		}

		if err := netlink.LinkAdd(vethHost); err != nil {
			return errors.WithStack(err)
		}

		if err := netlink.LinkSetUp(vethHost); err != nil {
			return errors.WithStack(err)
		}

		if err := netlink.LinkSetMaster(vethHost, bridgeLink); err != nil {
			return errors.WithStack(err)
		}

		vethContainer, err := netlink.LinkByName(containerVETHName)
		if err != nil {
			return errors.WithStack(err)
		}

		if err := netlink.LinkSetNsPid(vethContainer, pid); err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}

func vethName(container, network string) string {
	hash := sha256.Sum256([]byte(container + "_" + network))
	name := "cv" + hex.EncodeToString(hash[:])
	if len(name) > 14 {
		name = name[:14]
	}
	return name
}

func inflateImage(ctx context.Context, imageTag string, mirrors []string) error {
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

			return inflateBlob(resp.Body)
		}); err != nil {
			return err
		}
	}

	return nil
}

//nolint:gocyclo
func inflateBlob(r io.Reader) error {
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
