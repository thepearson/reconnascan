//go:build windows

package analyzer

import (
	"os/exec"
	"syscall"
)

// prepareCmd configures process creation flags on Windows to prevent console windows from popping up.
func prepareCmd(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= 0x08000000 // CREATE_NO_WINDOW
}

