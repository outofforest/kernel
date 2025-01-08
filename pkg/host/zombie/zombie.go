package zombie

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/outofforest/logger"
)

const (
	pidIndex       = 0
	commandIndex   = 1
	parentPIDIndex = 3
)

var procRegExp = regexp.MustCompile("^[0-9]+$")

// Run runs zombie killer. It awaits zombie processes and terminates all the child processes on exit.
func Run(ctx context.Context, sigCh <-chan os.Signal, appTerminatedCh <-chan struct{}) error {
	log := logger.Get(ctx)
	procFSPath, pid, err := findProcfs()
	if err != nil {
		return err
	}

	defer func() {
		// terminating all the processes may start after exit of the main logic, so we are sure
		// that no new process is started by the app.
		<-appTerminatedCh

		runningErr := errors.New("children processes are still running")
		timeout := time.After(time.Minute)
		for {
			err := func() error {
				children, err := subProcesses(procFSPath, pid)
				if err != nil {
					return err
				}

				log.Info("Terminating leftover processes", zap.Int("count", len(children)))

				var running uint32

				//nolint:nestif
				if len(children) > 0 {
					for _, properties := range children {
						childPID, err := strconv.Atoi(properties[pidIndex])
						if err != nil {
							return errors.WithStack(err)
						}

						proc, err := os.FindProcess(childPID)
						if err != nil {
							return errors.WithStack(err)
						}

						log := log.With(
							zap.Int("pid", childPID),
							zap.String("command", properties[commandIndex]),
						)

						running++
						select {
						case <-timeout:
							log.Error("Killing process")
							if err := proc.Signal(syscall.SIGKILL); err != nil &&
								!errors.Is(err, os.ErrProcessDone) {
								return errors.WithStack(err)
							}
						default:
							log.Warn("Terminating process")
							if err := proc.Signal(syscall.SIGTERM); err != nil &&
								!errors.Is(err, os.ErrProcessDone) {
								return errors.WithStack(err)
							}
							if err := proc.Signal(syscall.SIGINT); err != nil &&
								!errors.Is(err, os.ErrProcessDone) {
								return errors.WithStack(err)
							}
						}
					}
					return runningErr
				}
				return nil
			}()

			switch {
			case err == nil:
				log.Info("No more processes running. Exiting.")
				return
			case errors.Is(err, runningErr):
			default:
				log.Error("Error while terminating processes", zap.Error(err))
			}

			select {
			case <-time.After(time.Second):
			case <-sigCh:
				awaitZombie()
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return errors.WithStack(ctx.Err())
		case <-sigCh:
		}

		awaitZombie()
	}
}

func awaitZombie() {
	for {
		var status syscall.WaitStatus

		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		switch {
		case errors.Is(err, syscall.EINTR):
		case pid <= 0:
			return
		}
	}
}

func findProcfs() (string, string, error) {
	var procFSPath string
	var err error
	var pid string

	for _, target := range []string{"/proc"} {
		pid, err = os.Readlink(filepath.Join(target, "self"))
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return "", "", errors.WithStack(err)
		}
		procFSPath = target
		break
	}

	if err != nil {
		return "", "", errors.New("no mounted procfs found")
	}

	if pid != strconv.Itoa(os.Getpid()) {
		return "", "", errors.Errorf("pid %s read from procfs does not match the %d read from the syscall", pid,
			os.Getpid())
	}

	return procFSPath, pid, nil
}

func subProcesses(procFSPath, pid string) ([][]string, error) {
	procs, err := os.ReadDir(procFSPath)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	result := [][]string{}
	for _, procDir := range procs {
		if !procDir.IsDir() || !procRegExp.MatchString(procDir.Name()) {
			continue
		}

		statPath := filepath.Join(procFSPath, procDir.Name(), "stat")
		statRaw, err := os.ReadFile(statPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, errors.WithStack(err)
		}

		properties := strings.SplitN(string(statRaw), " ", parentPIDIndex+2)
		if properties[parentPIDIndex] != pid {
			continue
		}

		if err != nil {
			return nil, errors.WithStack(err)
		}

		result = append(result, properties)
	}

	return result, nil
}
