package main

import (
	"os"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/docker/docker/pkg/units"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/configs"
)

var (
	defaltCaps = []string{
		"CHOWN",
		"DAC_OVERRIDE",
		"FSETID",
		"FOWNER",
		"SETGID",
		"SETUID",
		"SETFCAP",
		"SETPCAP",
		"NET_BIND_SERVICE",
		"KILL",
		"AUDIT_WRITE",
	}
)

type cpuset struct {
	Cpus string `toml:"cpus"`
	Mems string `toml:"mems"`
}

type resource struct {
	CpuShares                    int64  `toml:"cpu_shares"`
	CpuQuota                     int64  `toml:"cpu_quota"`
	CpuPeriod                    int64  `toml:"cpu_period"`
	Cpuset                       cpuset `toml:"cpuset"`
	MemoryLimit                  string `toml:"memory_limit"`
	MemoryReservation            string `toml:"memory_reservation"`
	MemorySwap                   string `toml:"memory_swap"`
	BlkioThrottleReadBpsDevice   string `toml:"blkio_throttle_read_bps_device"`
	BlkioThrottleWriteBpsDevice  string `toml:"blkio_throttle_write_bps_device"`
	BlkioThrottleReadIOpsDevice  string `toml:"blkio_throttle_read_iops_device"`
	BlkioThrottleWriteIOpsDevice string `toml:"blkio_throttle_write_iops_device"`
	BlkioWeight                  int64  `toml:"blkio_weight"`
	BlkioWeightDevice            string `toml:"blkio_weight_device"`
	DisableOOMKiller             bool   `toml:"disable_oom_killer"`
}

type namespace struct {
	Type string `toml:"type"`
	Path string `toml:"path"`
}

type mount struct {
	Device      string `toml:"device"`
	Source      string `toml:"source"`
	Destination string `toml:"destination"`
	Options     string `toml:"flags"`
}

type network struct {
	Type              string `toml:"type"`
	Bridge            string `toml:"bridge"`
	MacAddress        string `toml:"mac_address"`
	Mtu               int    `toml:"mtu"`
	IPv4Address       string `toml:"ipv4_address"`
	IPv4Gateway       string `toml:"ipv4_gateway"`
	IPv6Address       string `toml:"ipv6_address"`
	IPv6Gateway       string `toml:"ipv6_gateway"`
	TxQueueLen        int    `toml:"txqueuelen"`
	HostInterfaceName string `toml:"host_interface_name"`
	EnableHairpinNat  bool   `toml:"enable_hairpin_nat"`
}

type rlimit struct {
	Hard int `toml:"hard"`
	Soft int `toml:"soft"`
}

type security struct {
	AppArmorProfile string   `toml:"apparmor_profile"`
	MaskedFiles     []string `toml:"masked_files"`
	ReadonlyFiles   []string `toml:"readonly_files"`
}

type config struct {
	Args              []string             `toml:"args"`
	Cwd               string               `toml:"cwd"`
	Env               []string             `toml:"env"`
	Uid               int                  `toml:"uid"`
	Gid               int                  `toml:"gid"`
	Readonly          bool                 `toml:"readonly"`
	Hostname          string               `toml:"hostname"`
	ParentDeathSignal int                  `toml:"parent_death_signal"`
	Capabilities      []string             `toml:"capabilities"`
	Namespaces        map[string]namespace `toml:"namespaces"`
	Resources         resource             `toml:"resources"`
	Mounts            []mount              `toml:"mounts"`
	Networks          map[string]network   `toml:"networks"`
	Rlimits           map[string]rlimit    `toml:"rlimits"`
	Security          security             `toml:"security"`
}

func (c *config) mounts() []*configs.Mount {
	var mounts []*configs.Mount
	for _, m := range c.Mounts {
		flags, data := parseOptions(m.Options)
		mounts = append(mounts, &configs.Mount{
			Device:      m.Device,
			Source:      m.Source,
			Destination: m.Destination,
			Flags:       flags,
			Data:        data,
		})
	}
	return mounts
}

func loadConfig(path string) (*config, error) {
	var c *config
	if _, err := toml.DecodeFile(path, &c); err != nil {
		return nil, err
	}
	return c, nil
}

func createContainerConfig(c *config, id string) (*configs.Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	myCgroupPath, err := cgroups.GetThisCgroupDir("devices")
	if err != nil {
		return nil, err
	}
	cfg := &configs.Config{
		Rootfs:            cwd,
		ParentDeathSignal: c.ParentDeathSignal,
		Capabilities:      c.Capabilities,
		Readonlyfs:        c.Readonly,
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWNS},
			{Type: configs.NEWUTS},
			{Type: configs.NEWIPC},
			{Type: configs.NEWPID},
			{Type: configs.NEWNET},
		}),
		Cgroups: &configs.Cgroup{
			Name:            id,
			Parent:          myCgroupPath,
			AllowAllDevices: false,
			AllowedDevices:  configs.DefaultAllowedDevices,
		},
		AppArmorProfile: c.Security.AppArmorProfile,
		Devices:         configs.DefaultAutoCreatedDevices,
		MaskPaths:       c.Security.MaskedFiles,
		ReadonlyPaths:   c.Security.ReadonlyFiles,
	}
	for name, ns := range c.Namespaces {
		switch ns.Type {
		case "host":
			cfg.Namespaces.Remove(getNamespaceType(name))
		default:
			cfg.Namespaces.Add(getNamespaceType(name), ns.Path)
		}
	}
	cfg.Mounts = append(cfg.Mounts, c.mounts()...)
	cfg.Cgroups.CpusetCpus = c.Resources.Cpuset.Cpus
	cfg.Cgroups.CpusetMems = c.Resources.Cpuset.Mems
	cfg.Cgroups.CpuShares = c.Resources.CpuShares
	cfg.Cgroups.CpuQuota = c.Resources.CpuQuota
	cfg.Cgroups.CpuPeriod = c.Resources.CpuPeriod
	cfg.Cgroups.BlkioWeight = c.Resources.BlkioWeight
	cfg.Cgroups.BlkioWeightDevice = c.Resources.BlkioWeightDevice
	if c.Resources.MemoryLimit != "" {
		memLimit, err := units.FromHumanSize(c.Resources.MemoryLimit)
		if err != nil {
			return nil, err
		}
		cfg.Cgroups.Memory = memLimit
	}
	if c.Resources.MemoryReservation != "" {
		memReservation, err := units.FromHumanSize(c.Resources.MemoryReservation)
		if err != nil {
			return nil, err
		}
		cfg.Cgroups.MemoryReservation = memReservation
	}
	cfg.Cgroups.MemorySwap = -1
	if c.Resources.MemorySwap != "" {
		memSwap, err := units.FromHumanSize(c.Resources.MemorySwap)
		if err != nil {
			return nil, err
		}
		cfg.Cgroups.MemorySwap = memSwap
	}
	for name, n := range c.Networks {
		cfg.Networks = append(cfg.Networks, &configs.Network{
			Type:              n.Type,
			Name:              name,
			Address:           n.IPv4Address,
			Gateway:           n.IPv4Gateway,
			IPv6Address:       n.IPv6Address,
			IPv6Gateway:       n.IPv6Gateway,
			TxQueueLen:        n.TxQueueLen,
			Mtu:               n.Mtu,
			MacAddress:        n.MacAddress,
			Bridge:            n.Bridge,
			HostInterfaceName: n.HostInterfaceName,
			HairpinMode:       n.EnableHairpinNat,
		})
	}
	return cfg, nil
}

func getNamespaceType(name string) configs.NamespaceType {
	switch name {
	case "net":
		return configs.NEWNET
	case "user":
		return configs.NEWUSER
	case "ipc":
		return configs.NEWIPC
	case "pid":
		return configs.NEWPID
	case "uts":
		return configs.NEWUTS
	case "mnt":
		return configs.NEWNS
	}
	return ""
}

// Parse fstab type mount options into mount() flags
// and device specific data
func parseOptions(options string) (int, string) {
	var (
		flag int
		data []string
	)
	flags := map[string]struct {
		clear bool
		flag  int
	}{
		"defaults":      {false, 0},
		"ro":            {false, syscall.MS_RDONLY},
		"rw":            {true, syscall.MS_RDONLY},
		"suid":          {true, syscall.MS_NOSUID},
		"nosuid":        {false, syscall.MS_NOSUID},
		"dev":           {true, syscall.MS_NODEV},
		"nodev":         {false, syscall.MS_NODEV},
		"exec":          {true, syscall.MS_NOEXEC},
		"noexec":        {false, syscall.MS_NOEXEC},
		"sync":          {false, syscall.MS_SYNCHRONOUS},
		"async":         {true, syscall.MS_SYNCHRONOUS},
		"dirsync":       {false, syscall.MS_DIRSYNC},
		"remount":       {false, syscall.MS_REMOUNT},
		"mand":          {false, syscall.MS_MANDLOCK},
		"nomand":        {true, syscall.MS_MANDLOCK},
		"atime":         {true, syscall.MS_NOATIME},
		"noatime":       {false, syscall.MS_NOATIME},
		"diratime":      {true, syscall.MS_NODIRATIME},
		"nodiratime":    {false, syscall.MS_NODIRATIME},
		"bind":          {false, syscall.MS_BIND},
		"rbind":         {false, syscall.MS_BIND | syscall.MS_REC},
		"unbindable":    {false, syscall.MS_UNBINDABLE},
		"runbindable":   {false, syscall.MS_UNBINDABLE | syscall.MS_REC},
		"private":       {false, syscall.MS_PRIVATE},
		"rprivate":      {false, syscall.MS_PRIVATE | syscall.MS_REC},
		"shared":        {false, syscall.MS_SHARED},
		"rshared":       {false, syscall.MS_SHARED | syscall.MS_REC},
		"slave":         {false, syscall.MS_SLAVE},
		"rslave":        {false, syscall.MS_SLAVE | syscall.MS_REC},
		"relatime":      {false, syscall.MS_RELATIME},
		"norelatime":    {true, syscall.MS_RELATIME},
		"strictatime":   {false, syscall.MS_STRICTATIME},
		"nostrictatime": {true, syscall.MS_STRICTATIME},
	}
	for _, o := range strings.Split(options, ",") {
		// If the option does not exist in the flags table or the flag
		// is not supported on the platform,
		// then it is a data value for a specific fs type
		if f, exists := flags[o]; exists && f.flag != 0 {
			if f.clear {
				flag &= ^f.flag
			} else {
				flag |= f.flag
			}
		} else {
			data = append(data, o)
		}
	}
	return flag, strings.Join(data, ",")
}
