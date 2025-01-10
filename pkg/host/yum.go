package host

import "sort"

// PackageListProvider lists packages used by all the hosts.
func PackageListProvider(config *Config) func() []string {
	return func() []string {
		m := map[string]struct{}{}
		for _, h := range config.Hosts {
			for _, p := range h.Packages {
				m[p] = struct{}{}
			}
		}
		packages := make([]string, 0, len(m))
		for p := range m {
			packages = append(packages, p)
		}

		sort.Strings(packages)
		return packages
	}
}
