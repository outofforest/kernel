package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"github.com/outofforest/cloudless/pkg/host"
	"github.com/outofforest/libexec"
	"github.com/outofforest/logger"
	"github.com/outofforest/parallel"
)

const (
	// Port is the port ssh server listens on.
	Port = 22

	shellPath = "/usr/bin/bash"
)

// NewService returns SSH service.
func NewService(authorizedKeys ...string) host.Service {
	return host.Service{
		Name:   "ssh",
		OnExit: parallel.Fail,
		TaskFn: func(ctx context.Context) error {
			if len(authorizedKeys) == 0 {
				return errors.New("no authorized keys specified")
			}

			authKeys := make([][]byte, 0, len(authorizedKeys))
			for _, k := range authorizedKeys {
				key, err := base64.RawStdEncoding.DecodeString(k)
				if err != nil {
					return errors.Wrapf(err, "failed to base64 decode key %q", k)
				}
				authKeys = append(authKeys, key)
			}

			_, privKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				return errors.WithStack(err)
			}

			signer, err := ssh.NewSignerFromKey(privKey)
			if err != nil {
				return errors.WithStack(err)
			}

			for {
				if err := runServer(ctx, signer, authKeys); err != nil {
					if errors.Is(err, ctx.Err()) {
						return err
					}
					logger.Get(ctx).Error("SSH server failed", zap.Error(err))
				}
			}
		},
	}
}

func runServer(ctx context.Context, signer ssh.Signer, authKeys [][]byte) error {
	l, err := net.Listen("tcp", ":"+strconv.Itoa(Port))
	if err != nil {
		return errors.WithStack(err)
	}
	defer l.Close()

	config := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: []string{"curve25519-sha256"},
			Ciphers:      []string{"aes256-gcm@openssh.com"},
			MACs:         []string{"hmac-sha2-512-etm@openssh.com"},
		},
		PublicKeyAuthAlgorithms: []string{"ssh-ed25519"},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			mKey := key.Marshal()
			for _, k := range authKeys {
				if bytes.Equal(mKey, k) {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errors.Errorf("unauthorized key %q", base64.RawStdEncoding.EncodeToString(mKey))
		},
	}
	config.AddHostKey(signer)

	return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
		spawn("watchdog", parallel.Fail, func(ctx context.Context) error {
			<-ctx.Done()
			_ = l.Close()
			return errors.WithStack(ctx.Err())
		})
		spawn("server", parallel.Fail, func(ctx context.Context) error {
			for {
				conn, err := l.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return errors.WithStack(ctx.Err())
					}
					return errors.WithStack(err)
				}

				spawn(fmt.Sprintf("client-%s", conn.RemoteAddr()), parallel.Continue, func(ctx context.Context) error {
					if err := client(ctx, conn, config); err != nil {
						logger.Get(ctx).Error("SSH session failed.", zap.Error(err))
					}

					return nil
				})
			}
		})

		return nil
	})
}

func client(ctx context.Context, conn net.Conn, config *ssh.ServerConfig) error {
	defer conn.Close()

	sConn, newCh, reqCh, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return errors.WithStack(err)
	}

	return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
		spawn("req", parallel.Exit, func(ctx context.Context) error {
			defer sConn.Close()

			for {
				select {
				case <-ctx.Done():
					return errors.WithStack(ctx.Err())
				case _, ok := <-reqCh:
					if !ok {
						return errors.WithStack(ctx.Err())
					}
				}
			}
		})
		spawn("channels", parallel.Exit, func(ctx context.Context) error {
			var chID uint64

			for chReq := range newCh {
				spawn(fmt.Sprintf("channel-%d", chID), parallel.Continue, func(ctx context.Context) error {
					if chReq.ChannelType() != "session" {
						if err := chReq.Reject(ssh.UnknownChannelType, "unknown channel type"); err != nil {
							return errors.WithStack(err)
						}
						return nil
					}

					ch, reqCh, err := chReq.Accept()
					if err != nil {
						return errors.WithStack(err)
					}

					return handler(ctx, ch, reqCh)
				})
			}

			return errors.WithStack(ctx.Err())
		})

		return nil
	})
}

func handler(ctx context.Context, ch ssh.Channel, reqCh <-chan *ssh.Request) error {
	ptm, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer ptm.Close()

	ptsName, err := name(ptm)
	if err != nil {
		return errors.WithStack(err)
	}
	if err := unlock(ptm); err != nil {
		return errors.WithStack(err)
	}

	pts, err := os.OpenFile(ptsName, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return errors.WithStack(err)
	}
	defer pts.Close()

	return parallel.Run(ctx, func(ctx context.Context, spawn parallel.SpawnFn) error {
		spawn("watchdog", parallel.Fail, func(ctx context.Context) error {
			defer ch.Close()
			defer ptm.Close()
			defer pts.Close()

			<-ctx.Done()
			return errors.WithStack(ctx.Err())
		})
		spawn("bash", parallel.Exit, func(ctx context.Context) error {
			cmd := exec.Command(shellPath)
			cmd.Dir = "/root"
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Setctty: true,
				Setsid:  true,
			}
			cmd.Stdin = pts
			cmd.Stdout = pts
			cmd.Stderr = pts

			return libexec.Exec(ctx, cmd)
		})
		spawn("copy1", parallel.Fail, func(ctx context.Context) error {
			_, err := io.Copy(ptm, ch)
			if ctx.Err() != nil {
				return errors.WithStack(ctx.Err())
			}
			return errors.WithStack(err)
		})
		spawn("copy2", parallel.Fail, func(ctx context.Context) error {
			_, err := io.Copy(ch, ptm)
			if ctx.Err() != nil {
				return errors.WithStack(ctx.Err())
			}
			return errors.WithStack(err)
		})
		spawn("req", parallel.Fail, func(ctx context.Context) error {
			for req := range reqCh {
				switch req.Type {
				case "shell":
					// We only accept the default shell
					// (i.e. no command in the Payload)
					if err := req.Reply(len(req.Payload) == 0, nil); err != nil {
						return errors.WithStack(err)
					}
				case "pty-req":
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					if err := setWinsize(ptm.Fd(), w, h); err != nil {
						return err
					}
					// Responding true (OK) here will let the client
					// know we have a pty ready for input
					if err := req.Reply(true, nil); err != nil {
						return errors.WithStack(err)
					}
				case "window-change":
					w, h := parseDims(req.Payload)
					if err := setWinsize(ptm.Fd(), w, h); err != nil {
						return err
					}
				}
			}

			<-ctx.Done()

			return errors.WithStack(ctx.Err())
		})
		return nil
	})
}

type winSize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

func setWinsize(fd uintptr, w, h uint32) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&winSize{
		Width:  uint16(w),
		Height: uint16(h),
	})))
	if err != 0 {
		return errors.WithStack(err)
	}

	return nil
}

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	return binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
}

func name(f *os.File) (string, error) {
	var n uint32
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
	if err != 0 {
		return "", errors.WithStack(err)
	}
	return "/dev/pts/" + strconv.Itoa(int(n)), nil
}

func unlock(f *os.File) error {
	var u int32
	// use TIOCSPTLCK with a pointer to zero to clear the lock.
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&u)))
	if err != 0 {
		return errors.WithStack(err)
	}
	return nil
}
