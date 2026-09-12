package vulndb

import "testing"

func TestRPMOSVEcosystems(t *testing.T) {
	for ns, want := range map[string]string{"rocky": "Rocky Linux", "almalinux": "AlmaLinux", "rhel": "Red Hat", "redhat": "Red Hat", "centos": "Red Hat", "opensuse-leap": "openSUSE", "openSUSE-tumbleweed": "openSUSE", "sles": "SUSE", "fedora": "", "amzn": "", "ol": "", "photon": ""} {
		if got := PURLTypeToEcosystem("rpm", ns); got != want {
			t.Errorf("%s: %q != %q", ns, got, want)
		}
	}
}
