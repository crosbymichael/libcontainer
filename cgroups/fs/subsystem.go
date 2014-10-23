package fs

import "github.com/docker/libcontainer/cgroups"

var subsystems = map[string]subsystem{
	"devices":    &DevicesGroup{},
	"memory":     &MemoryGroup{},
	"cpu":        &CpuGroup{},
	"cpuset":     &CpusetGroup{},
	"cpuacct":    &CpuacctGroup{},
	"blkio":      &BlkioGroup{},
	"perf_event": &PerfEventGroup{},
	"freezer":    &FreezerGroup{},
}

type subsystem interface {
	// Returns the stats, as 'stats', corresponding to the cgroup under 'path'.
	GetStats(path string, stats *cgroups.Stats) error

	// Removes the cgroup represented by 'data'.
	Remove(*data) error

	// Creates and joins the cgroup represented by data.
	Set(*data) error
}
