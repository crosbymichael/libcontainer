// +build linux

package namespaces

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/label"
	"github.com/dotcloud/docker/pkg/system"
)

func RunIn(container *libcontainer.Config, state *libcontainer.State, args []string, nsinitPath string, term Terminal, startCallback func(*exec.Cmd)) (int, error) {
	var (
		master  *os.File
		console string
		err     error
	)

	if container.Tty {
		master, console, err = system.CreateMasterAndConsole()
		if err != nil {
			return -1, err
		}
		term.SetMaster(master)
	}

	initArgs, err := getNsEnterCommand(strconv.Itoa(state.InitPid), container, console, args)
	if err != nil {
		return -1, err
	}

	cmd := exec.Command(nsinitPath, initArgs...)

	if err := term.Attach(cmd); err != nil {
		return -1, err
	}
	defer term.Close()

	if err := cmd.Start(); err != nil {
		return -1, err
	}

	if startCallback != nil {
		startCallback(cmd)
	}

	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return -1, err
		}
	}

	return cmd.ProcessState.Sys().(syscall.WaitStatus).ExitStatus(), nil
}

// ExecIn uses an existing pid and joins the pid's namespaces with the new command.
func ExecIn(container *libcontainer.Config, state *libcontainer.State, args []string) error {
	// Enter the namespace and then finish setup
	finalArgs, err := getNsEnterCommand(strconv.Itoa(state.InitPid), container, "", args)
	if err != nil {
		return err
	}

	if err := system.Execv(finalArgs[0], finalArgs[0:], os.Environ()); err != nil {
		return err
	}

	panic("unreachable")
}

func getContainerJson(container *libcontainer.Config) (string, error) {
	// TODO(vmarmol): If this gets too long, send it over a pipe to the child.
	// Marshall the container into JSON since it won't be available in the namespace.
	containerJson, err := json.Marshal(container)
	if err != nil {
		return "", err
	}

	return string(containerJson), nil
}

func getNsEnterCommand(initPid string, container *libcontainer.Config, console string, args []string) ([]string, error) {
	containerJson, err := getContainerJson(container)
	if err != nil {
		return nil, err
	}

	out := []string{
		"nsenter",
		"--nspid", initPid,
		"--containerjson", containerJson,
	}

	if console != "" {
		out = append(out, "--console", console)
	}
	out = append(out, "--")
	out = append(out, args...)

	return out, nil
}

// NsEnter is run after entering the namespace.
func NsEnter(container *libcontainer.Config, args []string) error {
	// clear the current processes env and replace it with the environment
	// defined on the container
	if err := LoadContainerEnvironment(container); err != nil {
		return err
	}

	if err := FinalizeNamespace(container); err != nil {
		return err
	}

	if container.ProcessLabel != "" {
		if err := label.SetProcessLabel(container.ProcessLabel); err != nil {
			return err
		}
	}

	if err := system.Execv(args[0], args[0:], container.Env); err != nil {
		return err
	}
	panic("unreachable")
}
