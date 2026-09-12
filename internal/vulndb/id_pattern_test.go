package vulndb

import "testing"

func TestValidIDAcceptsErrataWithColon(t *testing.T) {
	for _, id := range []string{"CVE-2024-1234", "GHSA-aaaa-bbbb-cccc", "ALPINE-13661", "RLSA-2019:0975", "ALSA-2024:1234", "SUSE-SU-2024:0001-1", "DW202402-001"} {
		if !validID(id) {
			t.Errorf("%s rejected", id)
		}
	}
	for _, id := range []string{"", "CVE", "-CVE-1", "CVE-2024-1234-", "CVE 2024", "RLSA-2019:", "x-\x1b[2J"} {
		if validID(id) {
			t.Errorf("%q accepted", id)
		}
	}
}
