package seccomp

import "syscall"

// Action is the type of action to perform when the filter is matched for the syscall.
type Action int

const (
	// Kill is an action that will kill the calling process when it tries to
	// access a syscall that is not allowed.
	Kill Action = iota - 3
	// Trap will trap the syscall from the calling process and by default return
	// an EPERM.
	Trap
	// Allow will allow the calling process to make the specified syscall.
	Allow
)

// Error returns an action that results in the process getting the specified
// error code when performing the syscall.
func Error(code syscall.Errno) Action {
	return Action(code)
}

type Syscall struct {
	syscall uint32
	action  Action
	errno   uint32
	args    []string
}

// Context represents a seccomp profile to be applied to a process.
type Context struct {
	syscalls map[uint32]Syscall
}

// New returns an initialized Context for use in building a seccomp profile.
func New() (*Context, error) {
	c := &Context{
		syscalls: make(map[uint32]Syscall),
	}
	for _, s := range requiredSyscalls {
		c.Add(s, Allow)
	}
	return c, nil
}

// Add adds the provided syscall to the context along with the intendened action
// and any arguments to filter on.
func (c *Context) Add(s uint32, action Action, args ...string) {
	c.syscalls[s] = Syscall{
		syscall: s,
		action:  action,
		args:    args,
	}
}

// Remove removes the specific syscall from the Context.
func (c *Context) Remove(s uint32) {
	delete(c.syscalls, s)
}

// Load loads the profile for the current process.
func (c *Context) Load() error {
	var (
		i      = 0
		num    = len(c.syscalls)
		filter = make([]sockFilter, num*2+3)
	)
	filter[i] = bpfFilter(syscall.BPF_LD+syscall.BPF_W+syscall.BPF_ABS, 0)
	i++
	for _, value := range c.syscalls {
		filter[i] = bpfJump(syscall.BPF_JMP+syscall.BPF_JEQ+syscall.BPF_K, value.syscall, 0, 1)
		i++
		var action uint32
		switch value.action {
		case Allow:
			action = SECCOMP_RET_ALLOW
		case Trap:
			action = SECCOMP_RET_TRAP
		case Kill:
			action = SECCOMP_RET_KILL
		default:
			action = SECCOMP_ACT_ERRNO(uint32(value.action))
		}
		filter[i] = bpfFilter(syscall.BPF_RET+syscall.BPF_K, action)
		i++
	}
	filter[i] = bpfFilter(syscall.BPF_RET+syscall.BPF_K, SECCOMP_RET_TRAP)
	i++
	filter[i] = bpfFilter(syscall.BPF_RET+syscall.BPF_K, SECCOMP_RET_KILL)
	i++
	if err := prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return scmpfilter(&sockFprog{
		len:  uint16(i),
		filt: filter,
	})
}
