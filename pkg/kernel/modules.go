package kernel

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/unix"
)

const (
	basePath    = "/usr/lib/modules"
	fileBuiltIn = "modules.builtin"
	fileDeps    = "modules.dep"
	fileAliases = "modules.alias"
	fileLoaded  = "/proc/modules"
)

// LoadModule loads kernel module.
func LoadModule(module string) error {
	release, err := Release()
	if err != nil {
		return err
	}

	releaseBase := filepath.Join(basePath, release)
	module, err = resolveModuleAlias(module, filepath.Join(releaseBase, fileAliases))
	if err != nil {
		return err
	}

	if isBuiltIn, err := isBuiltInModule(module, filepath.Join(releaseBase, fileBuiltIn)); err != nil || isBuiltIn {
		return err
	}

	modulesToLoad, err := findModulesToLoad(module, filepath.Join(releaseBase, fileDeps))
	if err != nil {
		return err
	}

	for i := len(modulesToLoad) - 1; i >= 0; i-- {
		m := modulesToLoad[i]
		loaded, err := isLoaded(m, fileLoaded)
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

func resolveModuleAlias(module string, fileAliases string) (string, error) {
	aliasF, err := os.Open(fileAliases)
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

func isBuiltInModule(module string, fileBuiltIn string) (bool, error) {
	builtInF, err := os.Open(fileBuiltIn)
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

func findModulesToLoad(module string, fileDeps string) ([]string, error) {
	depF, err := os.Open(fileDeps)
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
			return nil, errors.Errorf("module %q not found", module)
		default:
			return nil, errors.WithStack(err)
		}

		dotIndex := strings.Index(line, ".")
		if dotIndex < 0 {
			continue
		}

		if filepath.Base(line[:dotIndex]) != module {
			continue
		}

		colonIndex := strings.Index(line, ":")
		if colonIndex < 0 {
			continue
		}

		modulesToLoad := []string{
			line[:colonIndex],
		}

		if deps := strings.TrimSpace(line[colonIndex+1:]); deps != "" {
			for _, m := range strings.Split(deps, " ") {
				modulesToLoad = append(modulesToLoad, strings.TrimSpace(m))
			}
		}

		return modulesToLoad, nil
	}
}

func isLoaded(modulePath string, fileLoaded string) (bool, error) {
	module := strings.TrimSuffix(filepath.Base(modulePath), ".ko.xz")
	modulesF, err := os.Open(fileLoaded)
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
