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

func collectHostMetadata(osName, osVersion string) HostMetadata {
	hostname, _ := os.Hostname()
	cpuInfo, _ := os.ReadFile("/proc/cpuinfo")
	memInfo, _ := os.ReadFile("/proc/meminfo")
	kernel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return HostMetadata{
		Hostname:        hostname,
		OperatingSystem: osName,
		OSVersion:       osVersion,
		Kernel:          strings.TrimSpace(string(kernel)),
		Architecture:    runtime.GOARCH,
		CPUModel:        parseCPUModel(cpuInfo),
		CPUCount:        runtime.NumCPU(),
		MemoryBytes:     parseMemoryBytes(memInfo),
		IPAddresses:     hostIPAddresses(),
	}
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

func hostIPAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		value := ip.String()
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
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
