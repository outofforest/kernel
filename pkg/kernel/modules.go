package kernel

import (
	"bufio"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
)

const basePath = "/usr/lib/modules"

// LoadModule loads kernel module.
func LoadModule(realModule string) error {
	realModule, err := resolveModuleAlias(realModule)
	if err != nil {
		return err
	}

	if isBuiltIn, err := isBuiltInModule(realModule); err != nil || isBuiltIn {
		return err
	}

	modulePath, err := resolveModulePath(realModule)
	if err != nil {
		return err
	}

	modulesToLoad, err := findModulesToLoad(modulePath)
	if err != nil {
		return err
	}

	for _, m := range modulesToLoad {
		loaded, err := isLoaded(m)
		if err != nil {
			return err
		}
		if loaded {
			continue
		}

		if err := loadModule(m); err != nil {
			return err
		}
	}

	return nil
}

func resolveModuleAlias(module string) (string, error) {
	release, err := Release()
	if err != nil {
		return "", err
	}

	aliasF, err := os.Open(filepath.Join(basePath, release, "modules.alias"))
	if err != nil {
		return "", errors.WithStack(err)
	}
	defer aliasF.Close()

	reader := bufio.NewReader(aliasF)
	for {
		line, err := reader.ReadString('\n')
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return module, nil
		default:
			return "", errors.WithStack(err)
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		spaceIndex := strings.Index(line, " ")
		if spaceIndex < 0 {
			continue
		}
		line = line[spaceIndex+1:]
		spaceIndex = strings.Index(line, " ")
		if spaceIndex < 0 {
			continue
		}
		if line[:spaceIndex] != module {
			continue
		}
		return strings.TrimSpace(line[spaceIndex+1:]), nil
	}
}

func isBuiltInModule(module string) (bool, error) {
	release, err := Release()
	if err != nil {
		return false, err
	}

	builtInF, err := os.Open(filepath.Join(basePath, release, "modules.builtin"))
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer builtInF.Close()

	expectedModuleName := module + ".ko"
	reader := bufio.NewReader(builtInF)
	for {
		line, err := reader.ReadString('\n')
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return false, nil
		default:
			return false, errors.WithStack(err)
		}

		if filepath.Base(strings.TrimSpace(line)) == expectedModuleName {
			return true, nil
		}
	}
}

func resolveModulePath(module string) (string, error) {
	release, err := Release()
	if err != nil {
		return "", err
	}

	expectedFile := module + ".ko.xz"
	baseDir := filepath.Join(basePath, release)
	var modulePath string
	if err := filepath.WalkDir(filepath.Join(basePath, release), func(path string, d fs.DirEntry, err error) error {
		if filepath.Base(path) == expectedFile {
			modulePath = path
			return filepath.SkipAll
		}
		return nil
	}); err != nil {
		return "", err
	}

	if modulePath == "" {
		return "", errors.Errorf("module %q not found", module)
	}

	return strings.TrimPrefix(modulePath, baseDir+"/"), nil
}

func findModulesToLoad(modulePath string) ([]string, error) {
	modulesToLoad := []string{modulePath}

	release, err := Release()
	if err != nil {
		return nil, err
	}

	depF, err := os.Open(filepath.Join(basePath, release, "modules.dep"))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer depF.Close()

	reader := bufio.NewReader(depF)
	for {
		line, err := reader.ReadString('\n')
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return modulesToLoad, nil
		default:
			return nil, errors.WithStack(err)
		}

		spaceIndex := strings.Index(line, " ")
		if spaceIndex < 0 {
			continue
		}

		if line[:spaceIndex-1] != modulePath {
			continue
		}

		for _, m := range strings.Split(line[spaceIndex+1:], " ") {
			modulesToLoad = append(modulesToLoad, strings.TrimSpace(m))
		}

		return modulesToLoad, nil
	}
}

func isLoaded(modulePath string) (bool, error) {
	module := strings.TrimSuffix(filepath.Base(modulePath), ".ko.xz")
	modulesF, err := os.Open("/proc/modules")
	if err != nil {
		return false, errors.WithStack(err)
	}
	defer modulesF.Close()

	reader := bufio.NewReader(modulesF)
	for {
		line, err := reader.ReadString('\n')
		switch {
		case err == nil:
		case errors.Is(err, io.EOF):
			return false, nil
		default:
			return false, errors.WithStack(err)
		}

		spaceIndex := strings.Index(line, " ")
		if spaceIndex < 0 {
			continue
		}
		if line[:spaceIndex] != module {
			continue
		}
		line = line[spaceIndex+1:]
		spaceIndex = strings.Index(line, " ")
		if spaceIndex < 0 {
			continue
		}
		line = line[spaceIndex+1:]
		spaceIndex = strings.Index(line, " ")
		if spaceIndex < 0 {
			continue
		}
		return line[:spaceIndex] != "0", nil
	}
}

func loadModule(modulePath string) error {
	release, err := Release()
	if err != nil {
		return err
	}

	f, err := os.Open(filepath.Join(basePath, release, modulePath))
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
