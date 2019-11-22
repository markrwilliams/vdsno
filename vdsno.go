package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ptraceState int

const (
	ptraceEnterSyscall = ptraceState(iota)
	ptraceExitSyscall
)

func (state ptraceState) next() ptraceState {
	switch state {
	case ptraceEnterSyscall:
		return ptraceExitSyscall
	case ptraceExitSyscall:
		return ptraceEnterSyscall
	default:
		panic(fmt.Errorf("unknown state %v", state))
	}
}

func noProcess(err error) bool {
	if err == nil {
		return false
	} else if err == syscall.ESRCH || err == syscall.ECHILD {
		return true
	} else {
		return true
	}
}

func isExec(regs *syscall.PtraceRegs) bool {
	return regs.Orig_rax == syscall.SYS_EXECVE
}

func stackBoundaries(pid int) (uint64, uint64, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var startAddr, endAddr uint64

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 6 && fields[5] == "[stack]" {
			fmt.Sscanf(fields[0], "%x-%x", &startAddr, &endAddr)
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}

	return startAddr, endAddr, nil
}

func readMemory(pid int, remoteAddress uintptr, size uint64) ([]byte, error) {
	destination := make([]byte, size)

	local := syscall.Iovec{
		Base: &destination[0],
		Len:  size,
	}

	remote := syscall.Iovec{
		Base: (*byte)(unsafe.Pointer(remoteAddress)),
		Len:  size,
	}

	if _, _, err := unix.Syscall6(
		unix.SYS_PROCESS_VM_READV,
		uintptr(pid),
		uintptr(unsafe.Pointer(&local)),
		1,
		uintptr(unsafe.Pointer(&remote)),
		1,
		0,
	); err != 0 {
		return nil, err
	}

	return destination[:], nil
}

func writeMemory(pid int, remoteAddress uintptr, contents []byte) error {
	local := syscall.Iovec{
		Base: &contents[0],
		Len:  uint64(len(contents)),
	}

	remote := syscall.Iovec{
		Base: (*byte)(unsafe.Pointer(remoteAddress)),
		Len:  uint64(len(contents)),
	}

	if _, _, err := unix.Syscall6(
		unix.SYS_PROCESS_VM_WRITEV,
		uintptr(pid),
		uintptr(unsafe.Pointer(&local)),
		1,
		uintptr(unsafe.Pointer(&remote)),
		1,
		0,
	); err != 0 {
		return err
	}

	return nil
}

const (
	AT_NULL         uint64 = 0
	AT_SYSINFO_EHDR uint64 = 33
)

func rewriteAuxVector(stack []byte, stackStart, rsp uint64) error {
	// - argc
	//
	// - pointers to argv[0]...argv[n]
	//
	// - NULL
	//
	// - pointers to env[0]...env[n]
	//
	// - NULL
	//
	// - auxv[0]...axv[n]
	//
	// - AT_NULL

	pos := rsp - stackStart
	argc := binary.LittleEndian.Uint64(stack[pos:])
	binary.LittleEndian.PutUint64(stack[pos:], 1)
	pos += 8

	var argvIdx uint64
	for argvPointer := uint64(1); pos < uint64(len(stack)) && argvPointer != 0; pos += 8 {
		argvPointer = binary.LittleEndian.Uint64(stack[pos:])
		argvIdx++
	}
	argvIdx--

	if argvIdx > argc {
		return fmt.Errorf("found %d arguments expected %d", argvIdx, argc)
	}

	for envPointer := uint64(1); pos < uint64(len(stack)) && envPointer != 0; pos += 8 {
		envPointer = binary.LittleEndian.Uint64(stack[pos:])
	}

	var auxvEhdr, auxvEnd uint64
	for ; pos < uint64(len(stack)); pos += 16 {
		tag := binary.LittleEndian.Uint64(stack[pos:])
		switch tag {
		case AT_SYSINFO_EHDR:
			auxvEhdr = pos
		case AT_NULL:
			auxvEnd = pos
			break
		}
	}

	if auxvEnd == 0 || auxvEhdr == 0 {
		return fmt.Errorf("no aux vector found")
	}

	copy(stack[auxvEhdr:auxvEnd-16], stack[auxvEhdr+16:auxvEnd])
	for i := auxvEnd - 16; i < auxvEnd; i++ {
		stack[i] = 0
	}

	return nil
}

func main() {
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	cmd.Start()
	pid := cmd.Process.Pid

	regs := syscall.PtraceRegs{}

	state := ptraceExitSyscall

	for {
		if _, err := syscall.Wait4(pid, nil, 0, nil); noProcess(err) {
			break
		}

		if state == ptraceExitSyscall {
			if err := syscall.PtraceGetRegs(pid, &regs); noProcess(err) {
				break
			}
			if isExec(&regs) {
				stackStart, stackEnd, err := stackBoundaries(pid)
				if err != nil {
					panic(err)
				}

				stack, err := readMemory(pid, uintptr(stackStart), stackEnd-stackStart)
				if err != nil {
					panic(err)
				}

				err = rewriteAuxVector(stack, stackStart, uint64(regs.Rsp))
				if err != nil {
					panic(err)
				}

				if err := writeMemory(pid, uintptr(stackStart), stack); err != nil {
					panic(err)
				}

				if err = syscall.PtraceDetach(pid); err != nil {
					panic(err)
				}

				continue
			}
		}

		state = state.next()

		if err := syscall.PtraceSyscall(pid, 0); noProcess(err) {
			break
		}
	}
}
