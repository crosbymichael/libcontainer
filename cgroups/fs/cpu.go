package fs

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"

	"github.com/docker/libcontainer/cgroups"
)

const (
	shares    = "cpu.shares"
	cfsPeriod = "cpu.cfs_period_us"
	cfsQuota  = "cpu.cfs_quota_us"
	cpuStat   = "cpu.stat"
)

// /sys/fs/cgroup
// /sys/fs/cgroup/cpu/docker/1332432
func newCpuCgroup(root string, shares, period, quota int64) (*CpuGroup, error) {
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, err
	}

	if shares != 0 {
		if err := writeFile(root, shares, strconv.FormatInt(shares, 10)); err != nil {
			return nil, err
		}
	}
	if period != 0 {
		if err := writeFile(root, cfsPeriod, strconv.FormatInt(period, 10)); err != nil {
			return nil, err
		}
	}
	if quota != 0 {
		if err := writeFile(root, cfsQuota, strconv.FormatInt(quote, 10)); err != nil {
			return nil, err
		}
	}

	return &CpuGroup{
		root: root,
	}, nil
}

type CpuGroup struct {
	root string
}

func (c *CpuGroup) Stats(stats *cgroups.Stats) error {
	f, err := os.Open(filepath.Join(c.root, cpuStat))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := getCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}

		switch t {
		case "nr_periods":
			stats.CpuStats.ThrottlingData.Periods = v

		case "nr_throttled":
			stats.CpuStats.ThrottlingData.ThrottledPeriods = v

		case "throttled_time":
			stats.CpuStats.ThrottlingData.ThrottledTime = v
		}
	}
	return nil
}
