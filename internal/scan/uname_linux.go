//go:build linux

package scan

import "syscall"

// unameMachine returns uname(2)'s machine field ("x86_64", "aarch64"), or
// "" when the call fails.
func unameMachine() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return ""
	}
	b := make([]byte, 0, len(u.Machine))
	for _, c := range u.Machine {
		if c == 0 {
			break
		}
		b = append(b, byte(c)) // #nosec G115 -- Reinterpret the kernel char byte without changing its bit pattern.
	}
	return string(b)
}
