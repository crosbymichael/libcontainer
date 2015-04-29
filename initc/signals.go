package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/utils"
)

func newSignalHandler() *signalHandler {
	s := make(chan os.Signal, 1024)
	signal.Notify(s)
	return &signalHandler{
		signals: s,
	}
}

type exit struct {
	pid    int
	status int
}

type signalHandler struct {
	signals chan os.Signal
}

func (h *signalHandler) process(process *libcontainer.Process) (int, error) {
	pid1, err := process.Pid()
	if err != nil {
		return -1, err
	}
	for s := range h.signals {
		switch s {
		case syscall.SIGCHLD:
			exits, err := h.reapTheKids()
			if err != nil {
				logrus.Error(err)
			}
			for _, e := range exits {
				if e.pid == pid1 {
					return e.status, nil
				}
			}
		default:
			if err := process.Signal(s); err != nil {
				logrus.Error(err)
			}
		}
	}
	return -1, nil
}

func (h *signalHandler) reapTheKids() (exits []exit, err error) {
	for {
		var (
			ws  syscall.WaitStatus
			rus syscall.Rusage
		)
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, &rus)
		if err != nil {
			if err == syscall.ECHILD {
				return exits, nil
			}
			return nil, err
		}
		exits = append(exits, exit{
			pid:    pid,
			status: utils.ExitStatus(ws),
		})
	}
}
