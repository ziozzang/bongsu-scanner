package match

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

var fuzzSBOMSeeds = []string{
	`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1","version":1,"metadata":{"timestamp":"2026-09-17T00:00:00Z","component":{"bom-ref":"root","type":"application","name":"host","properties":[{"name":"bscan:host:operating-system","value":"debian"},{"name":"bscan:host:os-version","value":"13"},{"name":"bscan:os:codename","value":"trixie"}]}},"components":[{"bom-ref":"pkg:deb/debian/curl@8.14.1-2?arch=amd64&distro=debian-13","type":"library","name":"curl","version":"8.14.1-2","purl":"pkg:deb/debian/curl@8.14.1-2?arch=amd64&distro=debian-13&upstream=curl","properties":[{"name":"bscan:source","value":"var/lib/dpkg/status"}]},{"type":"operating-system","name":"debian","version":"13","properties":[{"name":"bscan:os:codename","value":"trixie"}]},{"bom-ref":"n1","type":"library","name":"lodash","purl":"pkg:npm/lodash@4.17.21","components":[{"bom-ref":"n2","name":"nested","purl":"pkg:npm/%40scope/nested@1.0.0"}]},{"bom-ref":"nopurl","name":"plain","version":"1"}]}`,
	`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"purl":"pkg:deb/ubuntu/x@1","properties":[{"name":"bscan:distro","value":"ubuntu-jammy"},{"name":"bscan:upstream","value":"src@2"}]},{"type":"operating-system","name":"ubuntu","version":"22.04"},{"purl":"pkg:apk/alpine/musl@1.2.5-r0?distro=alpine-3.20.3"},{"purl":"pkg:rpm/rocky/bash@5.2-1?distro=rocky-9.4"},{"purl":"pkg:rpm/opensuse/x@1?distro=opensuse-leap-15.6"},{"purl":"pkg:rpm/redhat/x@1?distro=rhel-9"},{"purl":"pkg:rpm/suse/x@1?distro=sles-15.6"}]}`,
	`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"bom-ref":"dup","name":"a"},{"bom-ref":"dup","name":"b"}]}`,
	`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"purl":"pkg:"}]}`,
	`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}`,
	`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":2,"version":null,"properties":[null,{"name":"d","value":"old"},{"name":"d","value":true}],"components":[{"name":"discard"}],"components":[{"name":"keep"}]}],"metadata":{"component":false}}`,
	`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"operating-system","name":"ubuntu","version":"24.04"},{"type":"operating-system","name":"debian","version":"13"},{"purl":"pkg:deb/debian/x@1"}]}`,
	`{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"host","packages":[{"SPDXID":"SPDXRef-Root","name":"host","packageComment":"bscan host metadata: {\"operating_system\":\"debian\",\"os_version\":\"13\"}","annotations":[{"comment":"bscan image metadata: {}"}]},{"SPDXID":"os","primaryPackagePurpose":"OPERATING-SYSTEM","name":"debian","versionInfo":"13"},{"SPDXID":"SPDXRef-Package-curl","name":"curl","versionInfo":"8.14.1-2","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:deb/debian/curl@8.14.1-2"},{"referenceType":"other","referenceLocator":"x"}]},{"SPDXID":"y","name":"y","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/override@2"}],"purl":"pkg:pypi/ignored@1"}]}`,
	`{"spdxVersion":"SPDX-2.2","packages":[{"name":"x","purl":"pkg:pypi/fallback@1","externalRefs":[]},"not an object",null,7]}`,
	`{"spdxVersion":"SPDX-3.0","packages":[]}`,
	`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a"}]} trailing`,
	`[]`, `{`, ``, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` + strings.Repeat(`{"components":[`, 50) + strings.Repeat(`]}`, 50) + `]}`,
}

func fuzzCheckDocument(t *testing.T, d Document) {
	t.Helper()
	refs := map[string]bool{}
	for _, s := range d.Subjects {
		if s.Ref == "" {
			t.Fatalf("subject without ref: %+v", s)
		}
		if refs[s.Ref] {
			t.Fatalf("duplicate subject ref %q", s.Ref)
		}
		refs[s.Ref] = true
		if s.PURL.Type != "" && s.Type != s.PURL.Type {
			t.Fatalf("subject type %q != purl type %q", s.Type, s.PURL.Type)
		}
		if s.Type == "operating-system" {
			t.Fatalf("operating-system component reported as subject: %+v", s)
		}
	}
	if d.Context.MixedOS && d.Context.OS != nil {
		t.Fatalf("mixed OS context still carries an OS: %+v", d.Context)
	}
}

// FuzzLoadSBOM checks that the in-memory loader and the streaming loader
// accept the same documents and derive the same matching inventory.
func FuzzLoadSBOM(f *testing.F) {
	for _, s := range fuzzSBOMSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		want, errLoad := loadCompactFile(data)
		got, errStream := loadStream(bytes.NewReader(data))
		if (errLoad == nil) != (errStream == nil) {
			t.Fatalf("loaders disagree: Load err=%v stream err=%v", errLoad, errStream)
		}
		if errLoad != nil {
			return
		}
		fuzzCheckDocument(t, want)
		fuzzCheckDocument(t, got)
		if got.Format != want.Format || !reflect.DeepEqual(got.Context, want.Context) {
			t.Fatalf("context diff:\n-%s %+v\n+%s %+v", want.Format, want.Context, got.Format, got.Context)
		}
		if !reflect.DeepEqual(got.Subjects, want.Subjects) {
			t.Fatalf("subject diff:\n-%+v\n+%+v", want.Subjects, got.Subjects)
		}
	})
}

func FuzzRelease(f *testing.F) {
	for _, eco := range []string{"Debian", "Ubuntu", "Alpine", "Rocky Linux", "AlmaLinux", "openSUSE", "SUSE", "Red Hat", "npm", ""} {
		for _, v := range []string{"debian-13", "bookworm", "ubuntu-22.04", "jammy", "alpine-3.20.3", "v3.20", "rocky-9.4", "almalinux-9", "opensuse-leap-15.6", "opensuse-tumbleweed-20240101", "sles-15.6", "sles-15.0", "rhel-9", "redhat-9.4", "centos-7", "centos-9", "SUSE:x", "", "."} {
			f.Add(eco, v)
		}
	}
	f.Fuzz(func(t *testing.T, eco, v string) {
		r := release(eco, v)
		if r != strings.TrimSpace(r) {
			t.Fatalf("release(%q, %q) = %q not trimmed", eco, v, r)
		}
		if eco == "Alpine" && r != "" && !strings.HasPrefix(r, "v") {
			t.Fatalf("release(%q, %q) = %q", eco, v, r)
		}
		if eco == "Red Hat" && r != "" && !strings.HasPrefix(strings.TrimSpace(v), "Red Hat:") && !isDigits(r) && !strings.HasPrefix(r, "centos-stream:") {
			t.Fatalf("release(%q, %q) = %q is neither a major version nor a CentOS Stream scope", eco, v, r)
		}
	})
}
