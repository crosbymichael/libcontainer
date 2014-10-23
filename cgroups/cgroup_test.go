package cgroups

import "testing"

func TestCgroup(t *testing.T) {
	// create a new cgroup hiarchy based on the configuration
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	// cleanup the hiarchy after we are done
	defer c.Cleanup()

	// add a new pid to the cgroup
	if err := c.Add(pid); err != nil {
		t.Fatal(err)
	}

	// Freeze all the processes inside the cgroup
	if err := c.Freeze(); err != nil {
		t.Fatal(err)
	}

	if err := c.Thaw(); err != nil {
		t.Fatal(err)
	}

	stats, err := c.GetStats()
	if err != nil {
		t.Fatal(err)
	}

	pids, err := c.GetPids()
	if err != nil {
		t.Fatal(err)
	}
}
