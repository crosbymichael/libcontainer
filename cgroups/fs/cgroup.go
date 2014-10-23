package fs

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/docker/libcontainer/cgroups"
)

var constructors = map[string]func(string, *cgroups.Config) (subsystem, error){
	"cpu": newCpuCgroup,
}

// New creates a new cgroup without any processes inside
func New(config *cgroups.Config) (cgroups.Cgroup, error) {
	groups := &FsCgroups{
		config:     config,
		subsystems: make(map[string]subsystem),
	}

	for name, constructor := range constructors {
		root := filepath.Join(cgroupRoot, name, config.Parent, config.Name)

		s, err := constructor(root, config)
		if err != nil {
			return nil, err
		}
		groups.subsystem[name] = s
	}
	return groups, nil
}

type FsCgroups struct {
	config    *cgroups.Config
	subsystem map[string]subsystem
}

func (f *FsCgroups) Add(pid int) error {
	for _, sys := range f.subsystems {
		if err := writeFile(sys.Root(), procsFile, strconv.Itoa(pid)); err != nil {
			return err
		}
	}
	return nil
}

func (f *FsCgroups) GetStats() (*cgroups.Stats, error) {
	stats := cgroups.NewStats()
	for _, sys := range f.subsystems {
		if err := sys.Stats(stats); err != nil {
			return nil, err
		}
	}
	return stats, nil
}

func (f *FsCgroups) Delete() error {
	for _, sys := range f.subsystems {
		os.RemoveAll(sys.Root())
	}
	return nil
}
