package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
)

var initCommand = cli.Command{
	Name: "_init_",
	Action: func(context *cli.Context) {
		runtime.GOMAXPROCS(1)
		runtime.LockOSThread()
		f, _ := libcontainer.New("")
		panic(f.StartInitialization())
	},
}

var configCommand = cli.Command{
	Name:  "config",
	Usage: "print out the default config template for a container",
	Action: func(context *cli.Context) {
		c := &config{
			Capabilities: defaltCaps,
			Cwd:          "/home",
			Uid:          1000,
			Gid:          1000,
			Env:          []string{"MYVAR=true"},
			Hostname:     "testcontainer",
			Mounts: []mount{
				{
					Source:      "proc",
					Destination: "/proc",
					Device:      "proc",
				},
				{
					Source:      "tmpfs",
					Destination: "/dev",
					Device:      "tmpfs",
					Options:     "nosuid,strictatime,mode=755",
				},
				{
					Source:      "devpts",
					Destination: "/dev/pts",
					Device:      "devpts",
					Options:     "nosuid,noexec,newinstance,ptmxmode=0666,mode=0620,gid=5",
				},
				{
					Device:      "tmpfs",
					Source:      "shm",
					Destination: "/dev/shm",
					Options:     "nosuid,noexec,nodev,mode=1777,size=65536k",
				},
				{
					Source:      "mqueue",
					Destination: "/dev/mqueue",
					Device:      "mqueue",
					Options:     "nosuid,noexec,nodev",
				},
				{
					Source:      "sysfs",
					Destination: "/sys",
					Device:      "sysfs",
					Options:     "nosuid,noexec,nodev,ro",
				},

				{
					Device:      "cgroup",
					Destination: "/sys/fs/cgroup",
					Options:     "ro",
				},
			},
			Security: security{
				AppArmorProfile: "docker-default",
			},
			Resources: resource{
				CpuShares:   200,
				MemoryLimit: "1024m",
				Cpuset: cpuset{
					Cpus: "0,1",
					Mems: "0,1",
				},
			},
			Namespaces: map[string]namespace{
				"net": namespace{
					Type: "host",
				},
			},
			Networks: map[string]network{
				"lo": network{
					Type:        "loopback",
					IPv4Address: "127.0.0.1/0",
					IPv4Gateway: "localhost",
				},
			},
			Readonly:          true,
			ParentDeathSignal: 9,
		}
		if err := toml.NewEncoder(os.Stdout).Encode(c); err != nil {
			logrus.Fatal(err)
		}
	},
}

func execAction(context *cli.Context) error {
	// create signal handler first thing so that if we receive any
	// signals from the time we start to the time we actually start
	// forwarding them to the container we can make sure that they
	// are queued up and ready for delivery.
	signals := newSignalHandler()
	if uid := os.Getuid(); uid != 0 {
		return fmt.Errorf("initc requires to be running as root")
	}
	c, err := loadConfig(context.GlobalString("config"))
	if err != nil {
		return err
	}
	f, err := libcontainer.New(context.GlobalString("root"), libcontainer.InitArgs(os.Args[0], "_init_"))
	if err != nil {
		return err
	}
	var (
		process = newProcess(context, c)
		id      = context.GlobalString("id")
	)
	ctConfig, err := createContainerConfig(c, id)
	if err != nil {
		return err
	}
	container, err := f.Create(id, ctConfig)
	if err != nil {
		return err
	}
	defer container.Destroy()
	if err := container.Start(process); err != nil {
		return err
	}
	status, err := signals.process(process)
	if err != nil {
		return err
	}
	process.Wait()
	container.Destroy()
	os.Exit(status)
	return nil
}
func fatal(err error) {
	if lerr, ok := err.(libcontainer.Error); ok {
		lerr.Detail(os.Stderr)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func defaltID() string {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Base(cwd)
}

func newProcess(context *cli.Context, c *config) *libcontainer.Process {
	args := c.Args
	if context.Args().Present() {
		args = context.Args()
	}
	return &libcontainer.Process{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		Args:   args,
		User:   fmt.Sprintf("%d:%d", c.Uid, c.Gid),
		Env:    os.Environ(),
		Cwd:    c.Cwd,
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "initc"
	app.Usage = "production ready container runtime"
	app.Author = "docker"
	app.Email = "initc@docker.com"
	app.Version = "1"
	app.Commands = []cli.Command{initCommand, configCommand}
	app.Flags = []cli.Flag{
		cli.StringFlag{Name: "root", Value: "/var/run/initc", Usage: "initc runtime state directory"},
		cli.StringFlag{Name: "id", Value: defaltID(), Usage: "container id"},
		cli.StringFlag{Name: "config,c", Value: "container.toml", Usage: "container configuration file"},
	}
	app.Action = func(context *cli.Context) {
		if err := execAction(context); err != nil {
			fatal(err)
		}
	}
	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
