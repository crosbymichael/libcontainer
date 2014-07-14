package nsinit

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"

	"github.com/codegangsta/cli"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/namespaces"
)

var execCommand = cli.Command{
	Name:   "exec",
	Usage:  "execute a new command inside a container",
	Action: execAction,
}

func execAction(context *cli.Context) {
	var exitCode int

	container, err := loadContainer()
	if err != nil {
		log.Fatal(err)
	}

	state, err := libcontainer.GetState(dataPath)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("unable to read state.json: %s", err)
	}

	term := namespaces.NewTerminal(os.Stdin, os.Stdout, os.Stderr, container.Tty)
	if state != nil {
		exitCode, err = namespaces.RunIn(container, state, []string(context.Args()), os.Args[0], term, func(cmd *exec.Cmd) {
			go forwardSignals(cmd)
		})
	} else {
		exitCode, err = startContainer(container, term, dataPath, []string(context.Args()))
	}

	if err != nil {
		log.Fatalf("failed to exec: %s", err)
	}

	os.Exit(exitCode)
}

// startContainer starts the container. Returns the exit status or -1 and an
// error.
//
// Signals sent to the current process will be forwarded to container.
func startContainer(container *libcontainer.Config, term namespaces.Terminal, dataPath string, args []string) (int, error) {
	var (
		cmd *exec.Cmd
	)

	createCommand := func(container *libcontainer.Config, console, rootfs, dataPath, init string, pipe *os.File, args []string) *exec.Cmd {
		cmd = namespaces.DefaultCreateCommand(container, console, rootfs, dataPath, init, pipe, args)
		if logPath != "" {
			cmd.Env = append(cmd.Env, fmt.Sprintf("log=%s", logPath))
		}

		return cmd
	}

	startCallback := func() {
		go forwardSignals(cmd)
	}

	return namespaces.Exec(container, term, "", dataPath, args, createCommand, startCallback)
}

func forwardSignals(cmd *exec.Cmd) {
	sigc := make(chan os.Signal, 10)
	signal.Notify(sigc)

	for sig := range sigc {
		cmd.Process.Signal(sig)
	}
}
