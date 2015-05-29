package main

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/utils"
)

const defaultMountFlags = syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV

var createFlags = []cli.Flag{
	cli.IntFlag{Name: "parent-death-signal", Usage: "set the signal that will be delivered to the process in case the parent dies"},
	cli.BoolFlag{Name: "read-only", Usage: "set the container's rootfs as read-only"},
	cli.StringSliceFlag{Name: "bind", Value: &cli.StringSlice{}, Usage: "add bind mounts to the container"},
	cli.StringSliceFlag{Name: "tmpfs", Value: &cli.StringSlice{}, Usage: "add tmpfs mounts to the container"},
	cli.IntFlag{Name: "cpushares", Usage: "set the cpushares for the container"},
	cli.IntFlag{Name: "memory-limit", Usage: "set the memory limit for the container"},
	cli.IntFlag{Name: "memory-swap", Usage: "set the memory swap limit for the container"},
	cli.StringFlag{Name: "cpuset-cpus", Usage: "set the cpuset cpus"},
	cli.StringFlag{Name: "cpuset-mems", Usage: "set the cpuset mems"},
	cli.StringFlag{Name: "apparmor-profile", Usage: "set the apparmor profile"},
	cli.StringFlag{Name: "process-label", Usage: "set the process label"},
	cli.StringFlag{Name: "mount-label", Usage: "set the mount label"},
	cli.StringFlag{Name: "rootfs", Usage: "set the rootfs"},
	cli.IntFlag{Name: "userns-root-uid", Usage: "set the user namespace root uid"},
	cli.StringFlag{Name: "hostname", Value: "nsinit", Usage: "hostname value for the container"},
	cli.StringFlag{Name: "net", Value: "", Usage: "network namespace"},
	cli.StringFlag{Name: "ipc", Value: "", Usage: "ipc namespace"},
	cli.StringFlag{Name: "pid", Value: "", Usage: "pid namespace"},
	cli.StringFlag{Name: "uts", Value: "", Usage: "uts namespace"},
	cli.StringFlag{Name: "mnt", Value: "", Usage: "mount namespace"},
	cli.StringFlag{Name: "veth-bridge", Usage: "veth bridge"},
	cli.StringFlag{Name: "veth-address", Usage: "veth ip address"},
	cli.StringFlag{Name: "veth-gateway", Usage: "veth gateway address"},
	cli.IntFlag{Name: "veth-mtu", Usage: "veth mtu"},
	cli.BoolFlag{Name: "cgroup", Usage: "mount the cgroup data for the container"},
	cli.StringSliceFlag{Name: "sysctl", Value: &cli.StringSlice{}, Usage: "set system properties in the container"},
	cli.StringSliceFlag{Name: "block-syscall", Value: &cli.StringSlice{}, Usage: "block a syscall"},
}

var configCommand = cli.Command{
	Name:  "config",
	Usage: "generate a standard configuration file for a container",
	Flags: append([]cli.Flag{
		cli.StringFlag{Name: "file,f", Value: "stdout", Usage: "write the configuration to the specified file"},
	}, createFlags...),
	Action: func(context *cli.Context) {
		template := getTemplate()
		modify(template, context)
		data, err := json.MarshalIndent(template, "", "\t")
		if err != nil {
			fatal(err)
		}
		var f *os.File
		filePath := context.String("file")
		switch filePath {
		case "stdout", "":
			f = os.Stdout
		default:
			if f, err = os.Create(filePath); err != nil {
				fatal(err)
			}
			defer f.Close()
		}
		if _, err := io.Copy(f, bytes.NewBuffer(data)); err != nil {
			fatal(err)
		}
	},
}

func modify(config *configs.Config, context *cli.Context) {
	config.ParentDeathSignal = context.Int("parent-death-signal")
	config.Readonlyfs = context.Bool("read-only")
	config.Cgroups.CpusetCpus = context.String("cpuset-cpus")
	config.Cgroups.CpusetMems = context.String("cpuset-mems")
	config.Cgroups.CpuShares = int64(context.Int("cpushares"))
	config.Cgroups.Memory = int64(context.Int("memory-limit"))
	config.Cgroups.MemorySwap = int64(context.Int("memory-swap"))
	config.AppArmorProfile = context.String("apparmor-profile")
	config.ProcessLabel = context.String("process-label")
	config.MountLabel = context.String("mount-label")

	rootfs := context.String("rootfs")
	if rootfs != "" {
		config.Rootfs = rootfs
	}

	userns_uid := context.Int("userns-root-uid")
	if userns_uid != 0 {
		config.Namespaces.Add(configs.NEWUSER, "")
		config.UidMappings = []configs.IDMap{
			{ContainerID: 0, HostID: userns_uid, Size: 1},
			{ContainerID: 1, HostID: 1, Size: userns_uid - 1},
			{ContainerID: userns_uid + 1, HostID: userns_uid + 1, Size: math.MaxInt32 - userns_uid},
		}
		config.GidMappings = []configs.IDMap{
			{ContainerID: 0, HostID: userns_uid, Size: 1},
			{ContainerID: 1, HostID: 1, Size: userns_uid - 1},
			{ContainerID: userns_uid + 1, HostID: userns_uid + 1, Size: math.MaxInt32 - userns_uid},
		}
		for _, node := range config.Devices {
			node.Uid = uint32(userns_uid)
			node.Gid = uint32(userns_uid)
		}
	}
	config.SystemProperties = make(map[string]string)
	for _, sysProp := range context.StringSlice("sysctl") {
		parts := strings.SplitN(sysProp, "=", 2)
		if len(parts) != 2 {
			logrus.Fatalf("invalid system property %s", sysProp)
		}
		config.SystemProperties[parts[0]] = parts[1]
	}
	for _, rawBind := range context.StringSlice("bind") {
		mount := &configs.Mount{
			Device: "bind",
			Flags:  syscall.MS_BIND | syscall.MS_REC,
		}
		parts := strings.SplitN(rawBind, ":", 3)
		switch len(parts) {
		default:
			logrus.Fatalf("invalid bind mount %s", rawBind)
		case 2:
			mount.Source, mount.Destination = parts[0], parts[1]
		case 3:
			mount.Source, mount.Destination = parts[0], parts[1]
			switch parts[2] {
			case "ro":
				mount.Flags |= syscall.MS_RDONLY
			case "rw":
			default:
				logrus.Fatalf("invalid bind mount mode %s", parts[2])
			}
		}
		config.Mounts = append(config.Mounts, mount)
	}
	for _, tmpfs := range context.StringSlice("tmpfs") {
		config.Mounts = append(config.Mounts, &configs.Mount{
			Device:      "tmpfs",
			Destination: tmpfs,
			Flags:       syscall.MS_NOEXEC | syscall.MS_NOSUID | syscall.MS_NODEV,
		})
	}
	for flag, value := range map[string]configs.NamespaceType{
		"net": configs.NEWNET,
		"mnt": configs.NEWNS,
		"pid": configs.NEWPID,
		"ipc": configs.NEWIPC,
		"uts": configs.NEWUTS,
	} {
		switch v := context.String(flag); v {
		case "host":
			config.Namespaces.Remove(value)
		case "", "private":
			if !config.Namespaces.Contains(value) {
				config.Namespaces.Add(value, "")
			}
			if flag == "net" {
				config.Networks = []*configs.Network{
					{
						Type:    "loopback",
						Address: "127.0.0.1/0",
						Gateway: "localhost",
					},
				}
			}
			if flag == "uts" {
				config.Hostname = context.String("hostname")
			}
		default:
			config.Namespaces.Remove(value)
			config.Namespaces.Add(value, v)
		}
	}
	if bridge := context.String("veth-bridge"); bridge != "" {
		hostName, err := utils.GenerateRandomName("veth", 7)
		if err != nil {
			logrus.Fatal(err)
		}
		network := &configs.Network{
			Type:              "veth",
			Name:              "eth0",
			Bridge:            bridge,
			Address:           context.String("veth-address"),
			Gateway:           context.String("veth-gateway"),
			Mtu:               context.Int("veth-mtu"),
			HostInterfaceName: hostName,
		}
		config.Networks = append(config.Networks, network)
	}
	if context.Bool("cgroup") {
		config.Mounts = append(config.Mounts, &configs.Mount{
			Destination: "/sys/fs/cgroup",
			Device:      "cgroup",
		})
	}
	if blocked := context.StringSlice("block-syscall"); len(blocked) > 0 {
		config.Seccomp = &configs.Seccomp{}
		for _, v := range syscalls {
			config.Seccomp.Syscalls = append(config.Seccomp.Syscalls, configs.Syscall{
				Value:  v,
				Action: configs.Allow,
			})
		}
		for _, s := range blocked {
			var set bool
			v, ok := syscalls[s]
			if !ok {
				logrus.Fatalf("syscall %s does not exist", s)
			}
			for i := range config.Seccomp.Syscalls {
				if config.Seccomp.Syscalls[i].Value == v {
					config.Seccomp.Syscalls[i].Action = configs.Action(syscall.EPERM)
					set = true
				}
			}
			if !set {
				logrus.Fatal("syscall for %s is not blocked", s)
			}
		}
	}
}

var syscalls = map[string]uint32{
	"READ":                   syscall.SYS_READ,
	"WRITE":                  syscall.SYS_WRITE,
	"OPEN":                   syscall.SYS_OPEN,
	"CLOSE":                  syscall.SYS_CLOSE,
	"STAT":                   syscall.SYS_STAT,
	"FSTAT":                  syscall.SYS_FSTAT,
	"LSTAT":                  syscall.SYS_LSTAT,
	"POLL":                   syscall.SYS_POLL,
	"LSEEK":                  syscall.SYS_LSEEK,
	"MMAP":                   syscall.SYS_MMAP,
	"MPROTECT":               syscall.SYS_MPROTECT,
	"MUNMAP":                 syscall.SYS_MUNMAP,
	"BRK":                    syscall.SYS_BRK,
	"RT_SIGACTION":           syscall.SYS_RT_SIGACTION,
	"RT_SIGPROCMASK":         syscall.SYS_RT_SIGPROCMASK,
	"RT_SIGRETURN":           syscall.SYS_RT_SIGRETURN,
	"IOCTL":                  syscall.SYS_IOCTL,
	"PREAD64":                syscall.SYS_PREAD64,
	"PWRITE64":               syscall.SYS_PWRITE64,
	"READV":                  syscall.SYS_READV,
	"WRITEV":                 syscall.SYS_WRITEV,
	"ACCESS":                 syscall.SYS_ACCESS,
	"PIPE":                   syscall.SYS_PIPE,
	"SELECT":                 syscall.SYS_SELECT,
	"SCHED_YIELD":            syscall.SYS_SCHED_YIELD,
	"MREMAP":                 syscall.SYS_MREMAP,
	"MSYNC":                  syscall.SYS_MSYNC,
	"MINCORE":                syscall.SYS_MINCORE,
	"MADVISE":                syscall.SYS_MADVISE,
	"SHMGET":                 syscall.SYS_SHMGET,
	"SHMAT":                  syscall.SYS_SHMAT,
	"SHMCTL":                 syscall.SYS_SHMCTL,
	"DUP":                    syscall.SYS_DUP,
	"DUP2":                   syscall.SYS_DUP2,
	"PAUSE":                  syscall.SYS_PAUSE,
	"NANOSLEEP":              syscall.SYS_NANOSLEEP,
	"GETITIMER":              syscall.SYS_GETITIMER,
	"ALARM":                  syscall.SYS_ALARM,
	"SETITIMER":              syscall.SYS_SETITIMER,
	"GETPID":                 syscall.SYS_GETPID,
	"SENDFILE":               syscall.SYS_SENDFILE,
	"SOCKET":                 syscall.SYS_SOCKET,
	"CONNECT":                syscall.SYS_CONNECT,
	"ACCEPT":                 syscall.SYS_ACCEPT,
	"SENDTO":                 syscall.SYS_SENDTO,
	"RECVFROM":               syscall.SYS_RECVFROM,
	"SENDMSG":                syscall.SYS_SENDMSG,
	"RECVMSG":                syscall.SYS_RECVMSG,
	"SHUTDOWN":               syscall.SYS_SHUTDOWN,
	"BIND":                   syscall.SYS_BIND,
	"LISTEN":                 syscall.SYS_LISTEN,
	"GETSOCKNAME":            syscall.SYS_GETSOCKNAME,
	"GETPEERNAME":            syscall.SYS_GETPEERNAME,
	"SOCKETPAIR":             syscall.SYS_SOCKETPAIR,
	"SETSOCKOPT":             syscall.SYS_SETSOCKOPT,
	"GETSOCKOPT":             syscall.SYS_GETSOCKOPT,
	"CLONE":                  syscall.SYS_CLONE,
	"FORK":                   syscall.SYS_FORK,
	"VFORK":                  syscall.SYS_VFORK,
	"EXECVE":                 syscall.SYS_EXECVE,
	"EXIT":                   syscall.SYS_EXIT,
	"WAIT4":                  syscall.SYS_WAIT4,
	"KILL":                   syscall.SYS_KILL,
	"UNAME":                  syscall.SYS_UNAME,
	"SEMGET":                 syscall.SYS_SEMGET,
	"SEMOP":                  syscall.SYS_SEMOP,
	"SEMCTL":                 syscall.SYS_SEMCTL,
	"SHMDT":                  syscall.SYS_SHMDT,
	"MSGGET":                 syscall.SYS_MSGGET,
	"MSGSND":                 syscall.SYS_MSGSND,
	"MSGRCV":                 syscall.SYS_MSGRCV,
	"MSGCTL":                 syscall.SYS_MSGCTL,
	"FCNTL":                  syscall.SYS_FCNTL,
	"FLOCK":                  syscall.SYS_FLOCK,
	"FSYNC":                  syscall.SYS_FSYNC,
	"FDATASYNC":              syscall.SYS_FDATASYNC,
	"TRUNCATE":               syscall.SYS_TRUNCATE,
	"FTRUNCATE":              syscall.SYS_FTRUNCATE,
	"GETDENTS":               syscall.SYS_GETDENTS,
	"GETCWD":                 syscall.SYS_GETCWD,
	"CHDIR":                  syscall.SYS_CHDIR,
	"FCHDIR":                 syscall.SYS_FCHDIR,
	"RENAME":                 syscall.SYS_RENAME,
	"MKDIR":                  syscall.SYS_MKDIR,
	"RMDIR":                  syscall.SYS_RMDIR,
	"CREAT":                  syscall.SYS_CREAT,
	"LINK":                   syscall.SYS_LINK,
	"UNLINK":                 syscall.SYS_UNLINK,
	"SYMLINK":                syscall.SYS_SYMLINK,
	"READLINK":               syscall.SYS_READLINK,
	"CHMOD":                  syscall.SYS_CHMOD,
	"FCHMOD":                 syscall.SYS_FCHMOD,
	"CHOWN":                  syscall.SYS_CHOWN,
	"FCHOWN":                 syscall.SYS_FCHOWN,
	"LCHOWN":                 syscall.SYS_LCHOWN,
	"UMASK":                  syscall.SYS_UMASK,
	"GETTIMEOFDAY":           syscall.SYS_GETTIMEOFDAY,
	"GETRLIMIT":              syscall.SYS_GETRLIMIT,
	"GETRUSAGE":              syscall.SYS_GETRUSAGE,
	"SYSINFO":                syscall.SYS_SYSINFO,
	"TIMES":                  syscall.SYS_TIMES,
	"PTRACE":                 syscall.SYS_PTRACE,
	"GETUID":                 syscall.SYS_GETUID,
	"SYSLOG":                 syscall.SYS_SYSLOG,
	"GETGID":                 syscall.SYS_GETGID,
	"SETUID":                 syscall.SYS_SETUID,
	"SETGID":                 syscall.SYS_SETGID,
	"GETEUID":                syscall.SYS_GETEUID,
	"GETEGID":                syscall.SYS_GETEGID,
	"SETPGID":                syscall.SYS_SETPGID,
	"GETPPID":                syscall.SYS_GETPPID,
	"GETPGRP":                syscall.SYS_GETPGRP,
	"SETSID":                 syscall.SYS_SETSID,
	"SETREUID":               syscall.SYS_SETREUID,
	"SETREGID":               syscall.SYS_SETREGID,
	"GETGROUPS":              syscall.SYS_GETGROUPS,
	"SETGROUPS":              syscall.SYS_SETGROUPS,
	"SETRESUID":              syscall.SYS_SETRESUID,
	"GETRESUID":              syscall.SYS_GETRESUID,
	"SETRESGID":              syscall.SYS_SETRESGID,
	"GETRESGID":              syscall.SYS_GETRESGID,
	"GETPGID":                syscall.SYS_GETPGID,
	"SETFSUID":               syscall.SYS_SETFSUID,
	"SETFSGID":               syscall.SYS_SETFSGID,
	"GETSID":                 syscall.SYS_GETSID,
	"CAPGET":                 syscall.SYS_CAPGET,
	"CAPSET":                 syscall.SYS_CAPSET,
	"RT_SIGPENDING":          syscall.SYS_RT_SIGPENDING,
	"RT_SIGTIMEDWAIT":        syscall.SYS_RT_SIGTIMEDWAIT,
	"RT_SIGQUEUEINFO":        syscall.SYS_RT_SIGQUEUEINFO,
	"RT_SIGSUSPEND":          syscall.SYS_RT_SIGSUSPEND,
	"SIGALTSTACK":            syscall.SYS_SIGALTSTACK,
	"UTIME":                  syscall.SYS_UTIME,
	"MKNOD":                  syscall.SYS_MKNOD,
	"USELIB":                 syscall.SYS_USELIB,
	"PERSONALITY":            syscall.SYS_PERSONALITY,
	"USTAT":                  syscall.SYS_USTAT,
	"STATFS":                 syscall.SYS_STATFS,
	"FSTATFS":                syscall.SYS_FSTATFS,
	"SYSFS":                  syscall.SYS_SYSFS,
	"GETPRIORITY":            syscall.SYS_GETPRIORITY,
	"SETPRIORITY":            syscall.SYS_SETPRIORITY,
	"SCHED_SETPARAM":         syscall.SYS_SCHED_SETPARAM,
	"SCHED_GETPARAM":         syscall.SYS_SCHED_GETPARAM,
	"SCHED_SETSCHEDULER":     syscall.SYS_SCHED_SETSCHEDULER,
	"SCHED_GETSCHEDULER":     syscall.SYS_SCHED_GETSCHEDULER,
	"SCHED_GET_PRIORITY_MAX": syscall.SYS_SCHED_GET_PRIORITY_MAX,
	"SCHED_GET_PRIORITY_MIN": syscall.SYS_SCHED_GET_PRIORITY_MIN,
	"SCHED_RR_GET_INTERVAL":  syscall.SYS_SCHED_RR_GET_INTERVAL,
	"MLOCK":                  syscall.SYS_MLOCK,
	"MUNLOCK":                syscall.SYS_MUNLOCK,
	"MLOCKALL":               syscall.SYS_MLOCKALL,
	"MUNLOCKALL":             syscall.SYS_MUNLOCKALL,
	"VHANGUP":                syscall.SYS_VHANGUP,
	"MODIFY_LDT":             syscall.SYS_MODIFY_LDT,
	"PIVOT_ROOT":             syscall.SYS_PIVOT_ROOT,
	"_SYSCTL":                syscall.SYS__SYSCTL,
	"PRCTL":                  syscall.SYS_PRCTL,
	"ARCH_PRCTL":             syscall.SYS_ARCH_PRCTL,
	"ADJTIMEX":               syscall.SYS_ADJTIMEX,
	"SETRLIMIT":              syscall.SYS_SETRLIMIT,
	"CHROOT":                 syscall.SYS_CHROOT,
	"SYNC":                   syscall.SYS_SYNC,
	"ACCT":                   syscall.SYS_ACCT,
	"SETTIMEOFDAY":           syscall.SYS_SETTIMEOFDAY,
	"MOUNT":                  syscall.SYS_MOUNT,
	"UMOUNT2":                syscall.SYS_UMOUNT2,
	"SWAPON":                 syscall.SYS_SWAPON,
	"SWAPOFF":                syscall.SYS_SWAPOFF,
	"REBOOT":                 syscall.SYS_REBOOT,
	"SETHOSTNAME":            syscall.SYS_SETHOSTNAME,
	"SETDOMAINNAME":          syscall.SYS_SETDOMAINNAME,
	"IOPL":                   syscall.SYS_IOPL,
	"IOPERM":                 syscall.SYS_IOPERM,
	"CREATE_MODULE":          syscall.SYS_CREATE_MODULE,
	"INIT_MODULE":            syscall.SYS_INIT_MODULE,
	"DELETE_MODULE":          syscall.SYS_DELETE_MODULE,
	"GET_KERNEL_SYMS":        syscall.SYS_GET_KERNEL_SYMS,
	"QUERY_MODULE":           syscall.SYS_QUERY_MODULE,
	"QUOTACTL":               syscall.SYS_QUOTACTL,
	"NFSSERVCTL":             syscall.SYS_NFSSERVCTL,
	"GETPMSG":                syscall.SYS_GETPMSG,
	"PUTPMSG":                syscall.SYS_PUTPMSG,
	"AFS_SYSCALL":            syscall.SYS_AFS_SYSCALL,
	"TUXCALL":                syscall.SYS_TUXCALL,
	"SECURITY":               syscall.SYS_SECURITY,
	"GETTID":                 syscall.SYS_GETTID,
	"READAHEAD":              syscall.SYS_READAHEAD,
	"SETXATTR":               syscall.SYS_SETXATTR,
	"LSETXATTR":              syscall.SYS_LSETXATTR,
	"FSETXATTR":              syscall.SYS_FSETXATTR,
	"GETXATTR":               syscall.SYS_GETXATTR,
	"LGETXATTR":              syscall.SYS_LGETXATTR,
	"FGETXATTR":              syscall.SYS_FGETXATTR,
	"LISTXATTR":              syscall.SYS_LISTXATTR,
	"LLISTXATTR":             syscall.SYS_LLISTXATTR,
	"FLISTXATTR":             syscall.SYS_FLISTXATTR,
	"REMOVEXATTR":            syscall.SYS_REMOVEXATTR,
	"LREMOVEXATTR":           syscall.SYS_LREMOVEXATTR,
	"FREMOVEXATTR":           syscall.SYS_FREMOVEXATTR,
	"TKILL":                  syscall.SYS_TKILL,
	"TIME":                   syscall.SYS_TIME,
	"FUTEX":                  syscall.SYS_FUTEX,
	"SCHED_SETAFFINITY":      syscall.SYS_SCHED_SETAFFINITY,
	"SCHED_GETAFFINITY":      syscall.SYS_SCHED_GETAFFINITY,
	"SET_THREAD_AREA":        syscall.SYS_SET_THREAD_AREA,
	"IO_SETUP":               syscall.SYS_IO_SETUP,
	"IO_DESTROY":             syscall.SYS_IO_DESTROY,
	"IO_GETEVENTS":           syscall.SYS_IO_GETEVENTS,
	"IO_SUBMIT":              syscall.SYS_IO_SUBMIT,
	"IO_CANCEL":              syscall.SYS_IO_CANCEL,
	"GET_THREAD_AREA":        syscall.SYS_GET_THREAD_AREA,
	"LOOKUP_DCOOKIE":         syscall.SYS_LOOKUP_DCOOKIE,
	"EPOLL_CREATE":           syscall.SYS_EPOLL_CREATE,
	"EPOLL_CTL_OLD":          syscall.SYS_EPOLL_CTL_OLD,
	"EPOLL_WAIT_OLD":         syscall.SYS_EPOLL_WAIT_OLD,
	"REMAP_FILE_PAGES":       syscall.SYS_REMAP_FILE_PAGES,
	"GETDENTS64":             syscall.SYS_GETDENTS64,
	"SET_TID_ADDRESS":        syscall.SYS_SET_TID_ADDRESS,
	"RESTART_SYSCALL":        syscall.SYS_RESTART_SYSCALL,
	"SEMTIMEDOP":             syscall.SYS_SEMTIMEDOP,
	"FADVISE64":              syscall.SYS_FADVISE64,
	"TIMER_CREATE":           syscall.SYS_TIMER_CREATE,
	"TIMER_SETTIME":          syscall.SYS_TIMER_SETTIME,
	"TIMER_GETTIME":          syscall.SYS_TIMER_GETTIME,
	"TIMER_GETOVERRUN":       syscall.SYS_TIMER_GETOVERRUN,
	"TIMER_DELETE":           syscall.SYS_TIMER_DELETE,
	"CLOCK_SETTIME":          syscall.SYS_CLOCK_SETTIME,
	"CLOCK_GETTIME":          syscall.SYS_CLOCK_GETTIME,
	"CLOCK_GETRES":           syscall.SYS_CLOCK_GETRES,
	"CLOCK_NANOSLEEP":        syscall.SYS_CLOCK_NANOSLEEP,
	"EXIT_GROUP":             syscall.SYS_EXIT_GROUP,
	"EPOLL_WAIT":             syscall.SYS_EPOLL_WAIT,
	"EPOLL_CTL":              syscall.SYS_EPOLL_CTL,
	"TGKILL":                 syscall.SYS_TGKILL,
	"UTIMES":                 syscall.SYS_UTIMES,
	"VSERVER":                syscall.SYS_VSERVER,
	"MBIND":                  syscall.SYS_MBIND,
	"SET_MEMPOLICY":          syscall.SYS_SET_MEMPOLICY,
	"GET_MEMPOLICY":          syscall.SYS_GET_MEMPOLICY,
	"MQ_OPEN":                syscall.SYS_MQ_OPEN,
	"MQ_UNLINK":              syscall.SYS_MQ_UNLINK,
	"MQ_TIMEDSEND":           syscall.SYS_MQ_TIMEDSEND,
	"MQ_TIMEDRECEIVE":        syscall.SYS_MQ_TIMEDRECEIVE,
	"MQ_NOTIFY":              syscall.SYS_MQ_NOTIFY,
	"MQ_GETSETATTR":          syscall.SYS_MQ_GETSETATTR,
	"KEXEC_LOAD":             syscall.SYS_KEXEC_LOAD,
	"WAITID":                 syscall.SYS_WAITID,
	"ADD_KEY":                syscall.SYS_ADD_KEY,
	"REQUEST_KEY":            syscall.SYS_REQUEST_KEY,
	"KEYCTL":                 syscall.SYS_KEYCTL,
	"IOPRIO_SET":             syscall.SYS_IOPRIO_SET,
	"IOPRIO_GET":             syscall.SYS_IOPRIO_GET,
	"INOTIFY_INIT":           syscall.SYS_INOTIFY_INIT,
	"INOTIFY_ADD_WATCH":      syscall.SYS_INOTIFY_ADD_WATCH,
	"INOTIFY_RM_WATCH":       syscall.SYS_INOTIFY_RM_WATCH,
	"MIGRATE_PAGES":          syscall.SYS_MIGRATE_PAGES,
	"OPENAT":                 syscall.SYS_OPENAT,
	"MKDIRAT":                syscall.SYS_MKDIRAT,
	"MKNODAT":                syscall.SYS_MKNODAT,
	"FCHOWNAT":               syscall.SYS_FCHOWNAT,
	"FUTIMESAT":              syscall.SYS_FUTIMESAT,
	"NEWFSTATAT":             syscall.SYS_NEWFSTATAT,
	"UNLINKAT":               syscall.SYS_UNLINKAT,
	"RENAMEAT":               syscall.SYS_RENAMEAT,
	"LINKAT":                 syscall.SYS_LINKAT,
	"SYMLINKAT":              syscall.SYS_SYMLINKAT,
	"READLINKAT":             syscall.SYS_READLINKAT,
	"FCHMODAT":               syscall.SYS_FCHMODAT,
	"FACCESSAT":              syscall.SYS_FACCESSAT,
	"PSELECT6":               syscall.SYS_PSELECT6,
	"PPOLL":                  syscall.SYS_PPOLL,
	"UNSHARE":                syscall.SYS_UNSHARE,
	"SET_ROBUST_LIST":        syscall.SYS_SET_ROBUST_LIST,
	"GET_ROBUST_LIST":        syscall.SYS_GET_ROBUST_LIST,
	"SPLICE":                 syscall.SYS_SPLICE,
	"TEE":                    syscall.SYS_TEE,
	"SYNC_FILE_RANGE":        syscall.SYS_SYNC_FILE_RANGE,
	"VMSPLICE":               syscall.SYS_VMSPLICE,
	"MOVE_PAGES":             syscall.SYS_MOVE_PAGES,
	"UTIMENSAT":              syscall.SYS_UTIMENSAT,
	"EPOLL_PWAIT":            syscall.SYS_EPOLL_PWAIT,
	"SIGNALFD":               syscall.SYS_SIGNALFD,
	"TIMERFD_CREATE":         syscall.SYS_TIMERFD_CREATE,
	"EVENTFD":                syscall.SYS_EVENTFD,
	"FALLOCATE":              syscall.SYS_FALLOCATE,
	"TIMERFD_SETTIME":        syscall.SYS_TIMERFD_SETTIME,
	"TIMERFD_GETTIME":        syscall.SYS_TIMERFD_GETTIME,
	"ACCEPT4":                syscall.SYS_ACCEPT4,
	"SIGNALFD4":              syscall.SYS_SIGNALFD4,
	"EVENTFD2":               syscall.SYS_EVENTFD2,
	"EPOLL_CREATE1":          syscall.SYS_EPOLL_CREATE1,
	"DUP3":                   syscall.SYS_DUP3,
	"PIPE2":                  syscall.SYS_PIPE2,
	"INOTIFY_INIT1":          syscall.SYS_INOTIFY_INIT1,
	"PREADV":                 syscall.SYS_PREADV,
	"PWRITEV":                syscall.SYS_PWRITEV,
	"RT_TGSIGQUEUEINFO":      syscall.SYS_RT_TGSIGQUEUEINFO,
	"PERF_EVENT_OPEN":        syscall.SYS_PERF_EVENT_OPEN,
	"RECVMMSG":               syscall.SYS_RECVMMSG,
	"FANOTIFY_INIT":          syscall.SYS_FANOTIFY_INIT,
	"FANOTIFY_MARK":          syscall.SYS_FANOTIFY_MARK,
	"PRLIMIT64":              syscall.SYS_PRLIMIT64,
}

func getTemplate() *configs.Config {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return &configs.Config{
		Rootfs:            cwd,
		ParentDeathSignal: int(syscall.SIGKILL),
		Capabilities: []string{
			"CHOWN",
			"DAC_OVERRIDE",
			"FSETID",
			"FOWNER",
			"MKNOD",
			"NET_RAW",
			"SETGID",
			"SETUID",
			"SETFCAP",
			"SETPCAP",
			"NET_BIND_SERVICE",
			"SYS_CHROOT",
			"KILL",
			"AUDIT_WRITE",
		},
		Namespaces: configs.Namespaces([]configs.Namespace{
			{Type: configs.NEWNS},
			{Type: configs.NEWUTS},
			{Type: configs.NEWIPC},
			{Type: configs.NEWPID},
			{Type: configs.NEWNET},
		}),
		Cgroups: &configs.Cgroup{
			Name:            filepath.Base(cwd),
			Parent:          "nsinit",
			AllowAllDevices: false,
			AllowedDevices:  configs.DefaultAllowedDevices,
		},
		Devices: configs.DefaultAutoCreatedDevices,
		MaskPaths: []string{
			"/proc/kcore",
		},
		ReadonlyPaths: []string{
			"/proc/sys", "/proc/sysrq-trigger", "/proc/irq", "/proc/bus",
		},
		Mounts: []*configs.Mount{
			{
				Source:      "proc",
				Destination: "/proc",
				Device:      "proc",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "tmpfs",
				Destination: "/dev",
				Device:      "tmpfs",
				Flags:       syscall.MS_NOSUID | syscall.MS_STRICTATIME,
				Data:        "mode=755",
			},
			{
				Source:      "devpts",
				Destination: "/dev/pts",
				Device:      "devpts",
				Flags:       syscall.MS_NOSUID | syscall.MS_NOEXEC,
				Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
			},
			{
				Device:      "tmpfs",
				Source:      "shm",
				Destination: "/dev/shm",
				Data:        "mode=1777,size=65536k",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "mqueue",
				Destination: "/dev/mqueue",
				Device:      "mqueue",
				Flags:       defaultMountFlags,
			},
			{
				Source:      "sysfs",
				Destination: "/sys",
				Device:      "sysfs",
				Flags:       defaultMountFlags | syscall.MS_RDONLY,
			},
		},
		Rlimits: []configs.Rlimit{
			{
				Type: syscall.RLIMIT_NOFILE,
				Hard: 1024,
				Soft: 1024,
			},
		},
	}

}
