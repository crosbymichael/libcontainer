// +build linux
// +build amd64

package seccomp

import (
	"syscall"
)

const (
	SECCOMP_RET_KILL    = 0x00000000
	SECCOMP_RET_TRAP    = 0x00030000
	SECCOMP_RET_ALLOW   = 0x7fff0000
	SECCOMP_MODE_FILTER = 0x2
	PR_SET_NO_NEW_PRIVS = 0x26
)

func SECCOMP_ACT_ERRNO(errno uint32) uint32 {
	return 0x00050000 | (errno & 0x0000ffff)
}

var requiredSyscalls = []uint32{
	syscall.SYS_WRITE,
	syscall.SYS_RT_SIGRETURN,
	syscall.SYS_EXIT_GROUP,
	syscall.SYS_FUTEX,
}
