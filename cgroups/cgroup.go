package cgroups

type Cgroup interface {
	// Add adds the current cgroup configuartion to the underlying system
	Add(pid int) error

	Freeze() error

	Thaw() error

	// GetPids returns all the process ids under the current cgroup
	GetPids() ([]int, error)

	// GetStats returns resource statistics for the current cgroup
	GetStats() (*Stats, error)

	// Config returns the cgroup configuration
	Config() *Config

	// Cleanup removes all the cgroup paths that were initialized
	Cleanup() error

	// Paths returns the cgroup paths for each sub system
	Paths() (map[string]string, error)
}
