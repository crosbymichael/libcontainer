package seccomp

import (
	"syscall"
	"unsafe"
)

type (
	sockFilter struct {
		code uint16
		jt   uint8
		jf   uint8
		k    uint32
	}
	sockFprog struct {
		len  uint16
		filt []sockFilter
	}
)

func prctl(option int, arg2, arg3, arg4, arg5 uintptr) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_PRCTL, uintptr(option), arg2, arg3, arg4, arg5, 0)
	if e1 != 0 {
		err = e1
	}
	return nil
}

func scmpfilter(prog *sockFprog) (err error) {
	_, _, e1 := syscall.Syscall(syscall.SYS_PRCTL, uintptr(syscall.PR_SET_SECCOMP),
		uintptr(SECCOMP_MODE_FILTER), uintptr(unsafe.Pointer(prog)))
	if e1 != 0 {
		err = e1
	}
	return nil
}

func bpfFilter(code uint16, k uint32) sockFilter {
	return sockFilter{code, 0, 0, k}
}

func bpfJump(code uint16, k uint32, jt, jf uint8) sockFilter {
	return sockFilter{code, jt, jf, k}
}
