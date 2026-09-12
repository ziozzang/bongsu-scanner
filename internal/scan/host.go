package scan

import (
	"bufio"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// virtualInterfacePrefixes name interfaces whose addresses describe
// container, VM or tunnel networks rather than the host itself.
var virtualInterfacePrefixes = []string{
	"docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "lxc", "tap", "tun",
}

func collectHostMetadata(osName, osVersion string) HostMetadata {
	cpuInfo, _ := os.ReadFile("/proc/cpuinfo")
	memInfo, _ := os.ReadFile("/proc/meminfo")
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return HostMetadata{
		Hostname:        hostName(),
		OperatingSystem: osName,
		OSVersion:       osVersion,
		Kernel:          strings.TrimSpace(string(kernel)),
		Architecture:    hostArchitecture(),
		CPUModel:        parseCPUModel(cpuInfo),
		CPUCount:        runtime.NumCPU(),
		MemoryBytes:     parseMemoryBytes(memInfo),
		IPAddresses:     hostIPAddresses(),
	}
}

// hostName prefers the kernel hostname and falls back to /etc/hostname.
func hostName() string {
	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSpace(h)
	}
	b, _ := os.ReadFile("/etc/hostname")
	return strings.TrimSpace(string(b))
}

// hostArchitecture reports the kernel machine name (uname -m: x86_64,
// aarch64, ...) so a 32-bit binary on a 64-bit kernel is not misreported;
// GOARCH is the fallback when uname is unavailable.
func hostArchitecture() string {
	if m := unameMachine(); m != "" {
		return m
	}
	return runtime.GOARCH
}

func parseCPUModel(data []byte) string {
	s := bufio.NewScanner(strings.NewReader(string(data)))
	for s.Scan() {
		line := s.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(line[:i]))
		if key == "model name" || key == "hardware" || key == "processor" {
			if value := strings.TrimSpace(line[i+1:]); value != "" && !allDigits(value) {
				return value
			}
		}
	}
	return ""
}

func parseMemoryBytes(data []byte) uint64 {
	s := bufio.NewScanner(strings.NewReader(string(data)))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kib, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil {
				return kib * 1024
			}
		}
	}
	return 0
}

// interfaceAddrs pairs an interface name with its addresses in CIDR form.
type interfaceAddrs struct {
	Name  string
	Addrs []string
}

// hostIPAddresses lists the host's routable addresses per interface,
// dropping loopback, unspecified, link-local and virtual-bridge addresses.
func hostIPAddresses() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var list []interfaceAddrs
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		entry := interfaceAddrs{Name: iface.Name}
		for _, a := range addrs {
			entry.Addrs = append(entry.Addrs, a.String())
		}
		list = append(list, entry)
	}
	return filterHostIPs(list)
}

// filterHostIPs applies the address policy to per-interface address lists
// and returns the sorted, deduplicated result.
func filterHostIPs(list []interfaceAddrs) []string {
	seen := map[string]bool{}
	var out []string
	for _, iface := range list {
		if virtualInterface(iface.Name) {
			continue
		}
		for _, addr := range iface.Addrs {
			ip, _, err := net.ParseCIDR(addr)
			if err != nil {
				ip = net.ParseIP(addr)
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() ||
				ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				continue
			}
			value := ip.String()
			if !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
	}
	sort.Strings(out)
	return out
}

func virtualInterface(name string) bool {
	for _, prefix := range virtualInterfacePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// detectContainer reports whether the scanner itself runs inside a
// container, in which case a "host" scan only sees the container.
func detectContainer() bool {
	_, err := os.Stat("/.dockerenv")
	cgroup, _ := os.ReadFile("/proc/1/cgroup")
	return inContainerFrom(err == nil, string(cgroup), loadMounts())
}

// inContainerFrom is the pure decision behind detectContainer: a
// /.dockerenv marker, a container runtime in PID 1's cgroup path, or an
// overlay filesystem mounted at "/".
func inContainerFrom(dockerEnv bool, cgroup string, mounts []mountEntry) bool {
	if dockerEnv {
		return true
	}
	for _, line := range strings.Split(cgroup, "\n") {
		for _, marker := range []string{"docker", "containerd", "kubepods", "lxc"} {
			if strings.Contains(line, marker) {
				return true
			}
		}
	}
	for _, m := range mounts {
		if m.MountPoint == "/" && m.FSType == "overlay" {
			return true
		}
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
