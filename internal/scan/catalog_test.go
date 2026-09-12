package scan

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// run catalogs the given path->content files and indexes the result by purl.
func run(t *testing.T, files map[string]string) (map[string]Package, []Package, *OSRelease) {
	t.Helper()
	var fs []File
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fs = append(fs, File{Path: p, Data: []byte(files[p])})
	}
	pkgs, osr := catalog(fs, nil)
	byPURL := map[string]Package{}
	for _, p := range pkgs {
		byPURL[p.PURL] = p
	}
	return byPURL, pkgs, osr
}

func purls(pkgs []Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, p.PURL)
	}
	sort.Strings(out)
	return out
}

func wantPURLs(t *testing.T, pkgs []Package, want ...string) {
	t.Helper()
	sort.Strings(want)
	if got := purls(pkgs); !reflect.DeepEqual(got, want) {
		t.Fatalf("purls mismatch\n got: %s\nwant: %s", strings.Join(got, "\n      "), strings.Join(want, "\n      "))
	}
}

func TestBuildPURL(t *testing.T) {
	cases := []struct {
		in   Package
		want string
	}{
		{Package{Type: "npm", Name: "@0no-co/graphql.web", Version: "1.0.11"}, "pkg:npm/%400no-co/graphql.web@1.0.11"},
		{Package{Type: "npm", Namespace: "@Scope", Name: "Name", Version: "1.0.0"}, "pkg:npm/%40scope/name@1.0.0"},
		{Package{Type: "npm", Name: "lodash", Version: "4.17.21"}, "pkg:npm/lodash@4.17.21"},
		{Package{Type: "deb", Namespace: "debian", Name: "curl", Version: "8.14.1-2+deb13u3", Arch: "amd64", Distro: "debian-13"}, "pkg:deb/debian/curl@8.14.1-2%2Bdeb13u3?arch=amd64&distro=debian-13"},
		{Package{Type: "deb", Namespace: "debian", Name: "libexpat1", Version: "2.7.1-2", Arch: "amd64", Distro: "debian-13", SourceName: "expat"}, "pkg:deb/debian/libexpat1@2.7.1-2?arch=amd64&distro=debian-13&upstream=expat"},
		{Package{Type: "deb", Namespace: "debian", Name: "git", Version: "1:2.47.3-0+deb13u1", Arch: "amd64", Distro: "debian-13"}, "pkg:deb/debian/git@1:2.47.3-0%2Bdeb13u1?arch=amd64&distro=debian-13"},
		{Package{Type: "deb", Name: "libssl1.1", Version: "1.1.1n-0+deb11u5", Arch: "arm64", SourceName: "openssl", SourceVersion: "1.1.1n-0+deb11u5"}, "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u5?arch=arm64&upstream=openssl"},
		{Package{Type: "deb", Namespace: "ubuntu", Name: "libc6", Version: "2.35-0ubuntu3.8", Arch: "amd64", Distro: "ubuntu-22.04", SourceName: "glibc", SourceVersion: "2.35-0ubuntu3.9"}, "pkg:deb/ubuntu/libc6@2.35-0ubuntu3.8?arch=amd64&distro=ubuntu-22.04&upstream=glibc%402.35-0ubuntu3.9"},
		{Package{Type: "deb", Name: "Curl", Version: "1.0"}, "pkg:deb/debian/curl@1.0"},
		{Package{Type: "deb", Name: "curl", Version: "1.0", SourceName: "curl"}, "pkg:deb/debian/curl@1.0"},
		{Package{Type: "golang", Name: "github.com/creack/pty", Version: "v1.1.9"}, "pkg:golang/github.com/creack/pty@v1.1.9"},
		{Package{Type: "golang", Name: "github.com/Masterminds/semver", Version: "v3.2.1"}, "pkg:golang/github.com/Masterminds/semver@v3.2.1"},
		{Package{Type: "golang", Name: "stdlib", Version: "1.22.4"}, "pkg:golang/stdlib@1.22.4"},
		{Package{Type: "golang", Name: "gopkg.in/yaml.v3", Version: "v3.0.1"}, "pkg:golang/gopkg.in/yaml.v3@v3.0.1"},
		{Package{Type: "golang", Name: "golang.org/x/net", Version: "v0.0.0-20220127200216-c8cf1f4d0f07+incompatible"}, "pkg:golang/golang.org/x/net@v0.0.0-20220127200216-c8cf1f4d0f07%2Bincompatible"},
		{Package{Type: "pypi", Name: "PyYAML", Version: "6.0.1"}, "pkg:pypi/pyyaml@6.0.1"},
		{Package{Type: "pypi", Name: "Zope.Interface_Foo", Version: "1"}, "pkg:pypi/zope-interface-foo@1"},
		{Package{Type: "apk", Namespace: "alpine", Name: "libssl3", Version: "3.1.4-r5", Arch: "x86_64", Distro: "alpine-3.19.1", SourceName: "openssl"}, "pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl"},
		{Package{Type: "apk", Name: "musl", Version: "1.2.4-r2", SourceName: "musl"}, "pkg:apk/alpine/musl@1.2.4-r2"},
		{Package{Type: "apk", Namespace: "wolfi", Name: "glibc", Version: "2.39-r1", Arch: "x86_64", Distro: "wolfi-20230201"}, "pkg:apk/wolfi/glibc@2.39-r1?arch=x86_64&distro=wolfi-20230201"},
		{Package{Type: "maven", Namespace: "org.apache.commons", Name: "commons-lang3", Version: "3.12.0"}, "pkg:maven/org.apache.commons/commons-lang3@3.12.0"},
		{Package{Type: "cargo", Name: "serde", Version: "1.0.197"}, "pkg:cargo/serde@1.0.197"},
		{Package{Type: "composer", Name: "laravel/framework", Version: "v10.0.0"}, "pkg:composer/laravel/framework@v10.0.0"},
		{Package{Type: "gem", Name: "rails", Version: "7.0.4"}, "pkg:gem/rails@7.0.4"},
		{Package{Type: "nuget", Name: "Newtonsoft.Json", Version: "13.0.1"}, "pkg:nuget/Newtonsoft.Json@13.0.1"},
		{Package{Type: "generic", Name: "a b#c?d", Version: "1 2"}, "pkg:generic/a%20b%23c%3Fd@1%202"},
		{Package{Type: "", Name: "x"}, ""},
		{Package{Type: "deb", Name: ""}, ""},
	}
	for _, c := range cases {
		if got := buildPURL(c.in); got != c.want {
			t.Errorf("buildPURL(%+v)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	if got := makePURL("npm", "@a/b", "1"); got != "pkg:npm/%40a/b@1" {
		t.Errorf("makePURL wrapper = %q", got)
	}
}

func TestPurlEncode(t *testing.T) {
	if got := purlEncode("A-z0._~@:+#?/ %"); got != "A-z0._~%40:%2B%23%3F%2F%20%25" {
		t.Fatalf("purlEncode = %q", got)
	}
	if got := purlEncodeNamespace("github.com/@foo/bar"); got != "github.com/%40foo/bar" {
		t.Fatalf("purlEncodeNamespace = %q", got)
	}
}

const debianOS = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION=\"13 (trixie)\"\nVERSION_CODENAME=trixie\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n"

func TestOSReleasePriority(t *testing.T) {
	alpine := "ID=alpine\nVERSION_ID=3.20.10\n"
	ubuntu := "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n"

	t.Run("nested copies are ignored", func(t *testing.T) {
		_, _, osr := run(t, map[string]string{
			"var/lib/docker/overlay2/abc/diff/etc/os-release": alpine,
			"home/user/project/testdata/os-release":           alpine,
			"etc/os-release":                                  debianOS,
		})
		if osr == nil || osr.ID != "debian" || osr.VersionID != "13" || osr.Codename != "trixie" || osr.PrettyName != "Debian GNU/Linux 13 (trixie)" {
			t.Fatalf("os-release = %+v", osr)
		}
		if got := osr.Distro(); got != "debian-13" {
			t.Fatalf("Distro() = %q", got)
		}
	})
	t.Run("only nested copies present yields nothing", func(t *testing.T) {
		_, _, osr := run(t, map[string]string{"var/lib/docker/overlay2/abc/diff/etc/os-release": alpine})
		if osr != nil {
			t.Fatalf("expected nil os-release, got %+v", osr)
		}
	})
	t.Run("etc wins over usr/lib regardless of order", func(t *testing.T) {
		for _, files := range []map[string]string{
			{"usr/lib/os-release": alpine, "etc/os-release": ubuntu},
			{"etc/os-release": ubuntu, "usr/lib/os-release": alpine},
		} {
			_, _, osr := run(t, files)
			if osr == nil || osr.ID != "ubuntu" || osr.IDLike != "debian" || osr.VersionID != "22.04" || osr.Codename != "jammy" {
				t.Fatalf("os-release = %+v", osr)
			}
		}
	})
	t.Run("usr/lib fallback and absolute host paths", func(t *testing.T) {
		_, _, osr := run(t, map[string]string{"/usr/lib/os-release": alpine})
		if osr == nil || osr.ID != "alpine" || osr.Distro() != "alpine-3.20.10" {
			t.Fatalf("os-release = %+v", osr)
		}
	})
	t.Run("distro applied to packages parsed before os-release", func(t *testing.T) {
		by, pkgs, _ := run(t, map[string]string{
			"a/var/lib/dpkg/status": "Package: nope\nStatus: install ok installed\nVersion: 1\n", // nested, ignored
			"var/lib/dpkg/status":   "Package: curl\nStatus: install ok installed\nVersion: 8.14.1-2+deb13u3\nArchitecture: amd64\n",
			"zzz/etc/os-release":    alpine, // nested, ignored
			"etc/os-release":        debianOS,
		})
		wantPURLs(t, pkgs, "pkg:deb/debian/curl@8.14.1-2%2Bdeb13u3?arch=amd64&distro=debian-13")
		p := by["pkg:deb/debian/curl@8.14.1-2%2Bdeb13u3?arch=amd64&distro=debian-13"]
		if p.Namespace != "debian" || p.Distro != "debian-13" || p.Arch != "amd64" {
			t.Fatalf("package = %+v", p)
		}
	})
}

func TestDpkgStatus(t *testing.T) {
	status := strings.Join([]string{
		"Package: libexpat1",
		"Status: install ok installed",
		"Priority: optional",
		"Section: libs",
		"Installed-Size: 415",
		"Maintainer: Debian XML/SGML Group <debian-xml-sgml-pkgs@lists.alioth.debian.org>",
		"Architecture: amd64",
		"Multi-Arch: same",
		"Source: expat",
		"Version: 2.7.1-2",
		"Description: XML parsing C library - runtime library",
		" This package contains the runtime, shared library of expat.",
		"",
		"Package: libssl1.1",
		"Status: install ok installed",
		"Architecture: amd64",
		"Source: openssl (1.1.1n-0+deb11u5)",
		"Version: 1.1.1n-0+deb11u5",
		"",
		"Package: git",
		"Status: install ok installed",
		"Architecture: amd64",
		"Version: 1:2.47.3-0+deb13u1",
		"",
		"Package: removed-pkg",
		"Status: deinstall ok config-files",
		"Architecture: amd64",
		"Version: 9",
		"",
		"Package: libc6:i386",
		"Status: install ok installed",
		"Version: 2.41-12",
		"Source: glibc (2.41-13)",
		"",
	}, "\n")
	by, pkgs, _ := run(t, map[string]string{"var/lib/dpkg/status": status, "etc/os-release": debianOS})
	wantPURLs(t, pkgs,
		"pkg:deb/debian/libexpat1@2.7.1-2?arch=amd64&distro=debian-13&upstream=expat",
		"pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u5?arch=amd64&distro=debian-13&upstream=openssl",
		"pkg:deb/debian/git@1:2.47.3-0%2Bdeb13u1?arch=amd64&distro=debian-13",
		"pkg:deb/debian/libc6@2.41-12?arch=i386&distro=debian-13&upstream=glibc%402.41-13",
	)
	ssl := by["pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u5?arch=amd64&distro=debian-13&upstream=openssl"]
	if ssl.SourceName != "openssl" || ssl.SourceVersion != "1.1.1n-0+deb11u5" || ssl.Source != "var/lib/dpkg/status" {
		t.Fatalf("libssl1.1 = %+v", ssl)
	}
	exp := by["pkg:deb/debian/libexpat1@2.7.1-2?arch=amd64&distro=debian-13&upstream=expat"]
	if exp.SourceName != "expat" || exp.SourceVersion != "" {
		t.Fatalf("libexpat1 = %+v", exp)
	}
}

func TestDpkgStatusDir(t *testing.T) {
	// distroless: one paragraph per file, no Status field, plus md5sums noise.
	by, pkgs, _ := run(t, map[string]string{
		"/etc/os-release":                        "ID=debian\nVERSION_ID=\"12\"\n",
		"/var/lib/dpkg/status.d/base-files":      "Package: base-files\nVersion: 12.4+deb12u5\nArchitecture: amd64\nMaintainer: x\n",
		"/var/lib/dpkg/status.d/libc6":           "Package: libc6\nVersion: 2.36-9+deb12u7\nArchitecture: amd64\nSource: glibc\n",
		"/var/lib/dpkg/status.d/libc6.md5sums":   "d41d8cd98f00b204e9800998ecf8427e  lib/x86_64-linux-gnu/libc.so.6\n",
		"/var/lib/dpkg/status.d/tzdata":          "Package: tzdata\nStatus: install ok installed\nVersion: 2024a-0+deb12u1\nArchitecture: all\n",
		"/var/lib/dpkg/status.d/not-installed":   "Package: gone\nStatus: deinstall ok config-files\nVersion: 1\nArchitecture: all\n",
		"/var/lib/dpkg/status.d/netbase.md5sums": "abc  etc/protocols\n",
	})
	wantPURLs(t, pkgs,
		"pkg:deb/debian/base-files@12.4%2Bdeb12u5?arch=amd64&distro=debian-12",
		"pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64&distro=debian-12&upstream=glibc",
		"pkg:deb/debian/tzdata@2024a-0%2Bdeb12u1?arch=all&distro=debian-12",
	)
	if p := by["pkg:deb/debian/libc6@2.36-9%2Bdeb12u7?arch=amd64&distro=debian-12&upstream=glibc"]; p.Source != "/var/lib/dpkg/status.d/libc6" {
		t.Fatalf("source = %q", p.Source)
	}
}

func TestApkInstalled(t *testing.T) {
	installed := strings.Join([]string{
		"C:Q1abc=",
		"P:libssl3",
		"V:3.1.4-r5",
		"A:x86_64",
		"S:1234",
		"I:5678",
		"T:SSL shared libraries",
		"U:https://www.openssl.org/",
		"L:Apache-2.0",
		"o:openssl",
		"m:Maintainer <m@example.org>",
		"t:1700000000",
		"c:deadbeef",
		"D:so:libc.musl-x86_64.so.1 so:libcrypto.so.3",
		"p:so:libssl.so.3=3",
		"",
		"P:musl",
		"V:1.2.4-r2",
		"A:x86_64",
		"L:MIT",
		"o:musl",
		"",
	}, "\n")
	t.Run("alpine", func(t *testing.T) {
		by, pkgs, _ := run(t, map[string]string{
			"lib/apk/db/installed": installed,
			"etc/os-release":       "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME=\"Alpine Linux v3.19\"\n",
		})
		wantPURLs(t, pkgs,
			"pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl",
			"pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1",
		)
		p := by["pkg:apk/alpine/libssl3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl"]
		if p.License != "Apache-2.0" || p.SourceName != "openssl" || p.Namespace != "alpine" || p.Distro != "alpine-3.19.1" {
			t.Fatalf("libssl3 = %+v", p)
		}
	})
	t.Run("wolfi under usr/lib", func(t *testing.T) {
		_, pkgs, _ := run(t, map[string]string{
			"usr/lib/apk/db/installed": "P:glibc\nV:2.39-r1\nA:x86_64\no:glibc\n",
			"usr/lib/os-release":       "ID=wolfi\nVERSION_ID=20230201\n",
		})
		wantPURLs(t, pkgs, "pkg:apk/wolfi/glibc@2.39-r1?arch=x86_64&distro=wolfi-20230201")
	})
	t.Run("no os-release defaults to alpine", func(t *testing.T) {
		_, pkgs, _ := run(t, map[string]string{"lib/apk/db/installed": "P:zlib\nV:1.3-r0\nA:aarch64\n"})
		wantPURLs(t, pkgs, "pkg:apk/alpine/zlib@1.3-r0?arch=aarch64")
	})
}

func TestNpmPackageLock(t *testing.T) {
	t.Run("v2/v3 packages map", func(t *testing.T) {
		lock := `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/@0no-co/graphql.web": {"version": "1.0.11", "license": "MIT"},
    "node_modules/lodash": {"version": "4.17.21", "dev": true},
    "node_modules/a/node_modules/@s/b": {"version": "2.0.0"},
    "node_modules/aliased": {"name": "real-name", "version": "3.0.0"},
    "node_modules/ws-link": {"resolved": "packages/ws", "link": true},
    "node_modules/noversion": {"dev": true},
    "packages/ws": {"name": "ws-pkg", "version": "0.0.1"}
  }
}`
		by, pkgs, _ := run(t, map[string]string{"app/package-lock.json": lock})
		wantPURLs(t, pkgs,
			"pkg:npm/%400no-co/graphql.web@1.0.11",
			"pkg:npm/lodash@4.17.21",
			"pkg:npm/%40s/b@2.0.0",
			"pkg:npm/real-name@3.0.0",
			"pkg:npm/ws-pkg@0.0.1",
		)
		g := by["pkg:npm/%400no-co/graphql.web@1.0.11"]
		if g.Namespace != "@0no-co" || g.Name != "graphql.web" || g.License != "MIT" || g.Dev {
			t.Fatalf("graphql.web = %+v", g)
		}
		if !by["pkg:npm/lodash@4.17.21"].Dev {
			t.Fatal("lodash should be dev")
		}
	})
	t.Run("v1 nested dependencies", func(t *testing.T) {
		lock := `{
  "lockfileVersion": 1,
  "dependencies": {
    "a": {"version": "1.0.0", "dependencies": {
        "@s/b": {"version": "2.0.0", "dev": true, "dependencies": {"c": {"version": "3.0.0"}}}
    }},
    "alias": {"version": "npm:real@4.0.0"},
    "local": {"version": "file:../local"},
    "gitdep": {"version": "git+https://github.com/x/y.git#abc"}
  }
}`
		by, pkgs, _ := run(t, map[string]string{"package-lock.json": lock})
		wantPURLs(t, pkgs, "pkg:npm/a@1.0.0", "pkg:npm/%40s/b@2.0.0", "pkg:npm/c@3.0.0", "pkg:npm/real@4.0.0")
		if !by["pkg:npm/%40s/b@2.0.0"].Dev || by["pkg:npm/c@3.0.0"].Dev {
			t.Fatalf("dev flags: %+v %+v", by["pkg:npm/%40s/b@2.0.0"], by["pkg:npm/c@3.0.0"])
		}
	})
	t.Run("hidden lockfile and shrinkwrap", func(t *testing.T) {
		_, pkgs, _ := run(t, map[string]string{
			"app/node_modules/.package-lock.json": `{"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.2.3"}}}`,
			"lib/npm-shrinkwrap.json":             `{"packages": {"node_modules/y": {"version": "2.0.0"}}}`,
		})
		wantPURLs(t, pkgs, "pkg:npm/x@1.2.3", "pkg:npm/y@2.0.0")
	})
}

func TestYarnLock(t *testing.T) {
	v1 := `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":
  version "7.10.4"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.10.4.tgz#abc"
  integrity sha512-xyz
  dependencies:
    "@babel/highlight" "^7.10.4"

lodash@^4.17.15, lodash@^4.17.20:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
`
	berry := `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 6
  cacheKey: 8

"@types/node@npm:^18.0.0":
  version: 18.11.9
  resolution: "@types/node@npm:18.11.9"
  checksum: abc
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  languageName: unknown
  linkType: soft

"react@npm:18.2.0":
  version: 18.2.0
  resolution: "react@npm:18.2.0"
`
	_, pkgs, _ := run(t, map[string]string{"a/yarn.lock": v1, "b/yarn.lock": berry})
	wantPURLs(t, pkgs,
		"pkg:npm/%40babel/code-frame@7.10.4",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/%40types/node@18.11.9",
		"pkg:npm/react@18.2.0",
	)
}

func TestPnpmLock(t *testing.T) {
	v6 := `lockfileVersion: '6.0'

settings:
  autoInstallPeers: true

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21

packages:

  /@babel/core@7.23.0(supports-color@5.5.0):
    resolution: {integrity: sha512-abc}
    engines: {node: '>=6.9.0'}
    dev: true

  /lodash@4.17.21:
    resolution: {integrity: sha512-def}
    dev: false

  /string_decoder@1.3.0:
    resolution: {integrity: sha512-ghi}
`
	v9 := `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      react:
        specifier: ^18.2.0
        version: 18.2.0

packages:

  '@types/react@18.2.45':
    resolution: {integrity: sha512-abc}

  react@18.2.0:
    resolution: {integrity: sha512-def}
    engines: {node: '>=0.10.0'}

snapshots:

  react@18.2.0:
    dependencies:
      loose-envify: 1.4.0
`
	v5 := `lockfileVersion: 5.4

packages:

  /@babel/core/7.0.0_supports-color@5.5.0:
    resolution: {integrity: sha512-abc}
    dev: true

  /string_decoder/1.3.0:
    resolution: {integrity: sha512-ghi}
`
	by, pkgs, _ := run(t, map[string]string{"a/pnpm-lock.yaml": v6, "b/pnpm-lock.yaml": v9, "c/pnpm-lock.yaml": v5})
	wantPURLs(t, pkgs,
		"pkg:npm/%40babel/core@7.23.0",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/string_decoder@1.3.0",
		"pkg:npm/%40types/react@18.2.45",
		"pkg:npm/react@18.2.0",
		"pkg:npm/%40babel/core@7.0.0",
	)
	if !by["pkg:npm/%40babel/core@7.23.0"].Dev || by["pkg:npm/lodash@4.17.21"].Dev {
		t.Fatalf("dev flags wrong: %+v", pkgs)
	}
	if got := by["pkg:npm/string_decoder@1.3.0"].Source; got != "a/pnpm-lock.yaml;c/pnpm-lock.yaml" {
		t.Fatalf("merged source = %q", got)
	}
}

func TestGoMod(t *testing.T) {
	gomod := `module github.com/example/app

go 1.22

toolchain go1.22.4

require (
	github.com/creack/pty v1.1.9
	github.com/old/lib v1.0.0
	"github.com/quoted/lib" v2.0.0+incompatible
	golang.org/x/text v0.14.0 // indirect
	example.com/local v0.1.0
	example.com/versioned v1.0.0
	example.com/versioned-other v1.0.0
)

require gopkg.in/yaml.v3 v3.0.1

replace github.com/old/lib => github.com/new/lib v1.5.0

replace (
	example.com/local => ../local
	example.com/versioned v1.0.0 => example.com/forked v1.0.1
	example.com/versioned-other v9.9.9 => example.com/never v0.0.1
)

exclude github.com/creack/pty v1.1.8
retract v1.0.0
`
	by, pkgs, _ := run(t, map[string]string{"src/go.mod": gomod})
	wantPURLs(t, pkgs,
		"pkg:golang/github.com/creack/pty@v1.1.9",
		"pkg:golang/github.com/new/lib@v1.5.0",
		"pkg:golang/github.com/quoted/lib@v2.0.0%2Bincompatible",
		"pkg:golang/golang.org/x/text@v0.14.0",
		"pkg:golang/example.com/forked@v1.0.1",
		"pkg:golang/example.com/versioned-other@v1.0.0",
		"pkg:golang/gopkg.in/yaml.v3@v3.0.1",
	)
	if !by["pkg:golang/golang.org/x/text@v0.14.0"].Indirect || by["pkg:golang/github.com/creack/pty@v1.1.9"].Indirect {
		t.Fatal("indirect flag wrong")
	}
	pty := by["pkg:golang/github.com/creack/pty@v1.1.9"]
	if pty.Namespace != "github.com/creack" || pty.Name != "pty" {
		t.Fatalf("pty = %+v", pty)
	}

	t.Run("go directive with patch, no toolchain", func(t *testing.T) {
		_, pkgs, _ := run(t, map[string]string{"go.mod": "module x\n\ngo 1.21.5\n\nrequire example.com/mod v1.2.3\n"})
		wantPURLs(t, pkgs, "pkg:golang/example.com/mod@v1.2.3")
	})
	t.Run("go directive without patch adds no stdlib", func(t *testing.T) {
		_, pkgs, _ := run(t, map[string]string{"go.mod": "module x\n\ngo 1.22\n\nrequire example.com/mod v1.2.3\n"})
		wantPURLs(t, pkgs, "pkg:golang/example.com/mod@v1.2.3")
	})
}

func TestRequirements(t *testing.T) {
	req := `# comment
-r base.txt
--index-url https://pypi.example.org/simple
-e git+https://github.com/x/y.git#egg=y
PyYAML==6.0.1
Django>=4.2,<5
requests[security]==2.32.3 ; python_version >= "3.8"
flask == 3.0.0  # inline comment
numpy~=1.26
click===8.1.7
cryptography==42.0.5 \
    --hash=sha256:aaaa \
    --hash=sha256:bbbb
urllib3
git+https://github.com/psf/black.git@stable
somepkg @ https://example.com/somepkg-1.0-py3-none-any.whl
localpkg @ file:///opt/localpkg
./vendor/pkg
wild==1.0.*
Zope_Interface<6
`
	by, pkgs, _ := run(t, map[string]string{"app/requirements.txt": req})
	wantPURLs(t, pkgs,
		"pkg:pypi/pyyaml@6.0.1",
		"pkg:pypi/django",
		"pkg:pypi/requests@2.32.3",
		"pkg:pypi/flask@3.0.0",
		"pkg:pypi/numpy",
		"pkg:pypi/click@8.1.7",
		"pkg:pypi/cryptography@42.0.5",
		"pkg:pypi/urllib3",
		"pkg:pypi/wild",
		"pkg:pypi/zope-interface",
	)
	if by["pkg:pypi/django"].Version != "" || by["pkg:pypi/cryptography@42.0.5"].Version != "42.0.5" {
		t.Fatalf("versions: %+v", pkgs)
	}
}

func TestPythonMetadata(t *testing.T) {
	metadata := `Metadata-Version: 2.1
Name: PyYAML
Version: 6.0.1
Summary: YAML parser and emitter for Python
License: MIT
        Long license body line two
        line three
Classifier: License :: OSI Approved :: MIT License

PyYAML is a YAML parser...
`
	withExpr := `Metadata-Version: 2.4
Name: cryptography
Version: 42.0.5
License: Apache-2.0 OR BSD-3-Clause legacy text
License-Expression: Apache-2.0 OR BSD-3-Clause
`
	pkgInfo := "Metadata-Version: 1.0\nName: setuptools_scm\nVersion: 8.0.4\nLicense: UNKNOWN\n"
	singleEgg := "Metadata-Version: 1.0\nName: legacy-egg\nVersion: 0.9\n"
	by, pkgs, _ := run(t, map[string]string{
		"usr/lib/python3/dist-packages/PyYAML-6.0.1.dist-info/METADATA":            metadata,
		"usr/lib/python3/dist-packages/cryptography-42.0.5.dist-info/METADATA":     withExpr,
		"usr/lib/python3/dist-packages/setuptools_scm-8.0.4.egg-info/PKG-INFO":     pkgInfo,
		"usr/lib/python3/dist-packages/legacy_egg-0.9-py3.11.egg-info":             singleEgg,
		"usr/lib/python3/dist-packages/random/METADATA":                            "Name: notpython\nVersion: 1\n", // wrong location: ignored by scanFile
		"usr/lib/python3/dist-packages/setuptools_scm-8.0.4.egg-info/requires.txt": "packaging>=20\n",
	})
	wantPURLs(t, pkgs,
		"pkg:pypi/pyyaml@6.0.1",
		"pkg:pypi/cryptography@42.0.5",
		"pkg:pypi/setuptools-scm@8.0.4",
		"pkg:pypi/legacy-egg@0.9",
	)
	if by["pkg:pypi/pyyaml@6.0.1"].License != "MIT" {
		t.Fatalf("license = %q", by["pkg:pypi/pyyaml@6.0.1"].License)
	}
	if by["pkg:pypi/cryptography@42.0.5"].License != "Apache-2.0 OR BSD-3-Clause" {
		t.Fatalf("license expression = %q", by["pkg:pypi/cryptography@42.0.5"].License)
	}
	if by["pkg:pypi/setuptools-scm@8.0.4"].License != "" {
		t.Fatal("UNKNOWN license should be dropped")
	}
}

func TestPythonLockfiles(t *testing.T) {
	poetry := `[[package]]
name = "attrs"
version = "23.1.0"
description = "Classes Without Boilerplate"
optional = false
python-versions = ">=3.7"
files = [
    {file = "attrs-23.1.0-py3-none-any.whl", hash = "sha256:abc"},
]

[package.dependencies]
version = "trap"
name = "trap"

[package.extras]
cov = ["attrs[tests]", "coverage[toml] (>=5.3)"]

[[package]]
name = "Pytest"
version = "7.4.0"
category = "dev"

[metadata]
lock-version = "2.0"
`
	uv := `version = 1
requires-python = ">=3.12"

[[package]]
name = "myproject"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "anyio" },
]

[[package]]
name = "anyio"
version = "4.4.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
]
sdist = { url = "https://files.pythonhosted.org/anyio-4.4.0.tar.gz", hash = "sha256:abc", size = 1 }

[package.metadata]
requires-dist = [
    { name = "idna", specifier = ">=2.8" },
]
`
	pipfile := `{
  "_meta": {"hash": {"sha256": "abc"}},
  "default": {
    "requests": {"hashes": ["sha256:abc"], "index": "pypi", "version": "==2.32.3"},
    "gitdep": {"git": "https://github.com/x/y.git", "ref": "abc"}
  },
  "develop": {
    "pytest": {"version": "==8.0.0"}
  }
}`
	by, pkgs, _ := run(t, map[string]string{"a/poetry.lock": poetry, "b/uv.lock": uv, "c/Pipfile.lock": pipfile})
	wantPURLs(t, pkgs,
		"pkg:pypi/attrs@23.1.0",
		"pkg:pypi/pytest@7.4.0",
		"pkg:pypi/anyio@4.4.0",
		"pkg:pypi/requests@2.32.3",
		"pkg:pypi/pytest@8.0.0",
	)
	if !by["pkg:pypi/pytest@7.4.0"].Dev || !by["pkg:pypi/pytest@8.0.0"].Dev || by["pkg:pypi/requests@2.32.3"].Dev {
		t.Fatalf("dev flags: %+v", pkgs)
	}
}

func TestCargoMavenGemComposerNuGet(t *testing.T) {
	cargo := `# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "myapp"
version = "0.1.0"
dependencies = [
 "serde",
]

[[package]]
name = "serde"
version = "1.0.197"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "gitcrate"
version = "0.3.0"
source = "git+https://github.com/x/gitcrate?rev=abc#abc"

[[patch.unused]]
name = "unused-patch"
version = "9.9.9"

[metadata]
"checksum foo 1.0.0" = "abc"
`
	pom := "#Generated by Maven\ngroupId=org.apache.commons\nartifactId=commons-lang3\nversion=3.12.0\n"
	gemfile := `GIT
  remote: https://github.com/x/y.git
  revision: abc
  specs:
    gitgem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
      actionpack (= 7.0.4)
      nio4r (~> 2.0)
    nokogiri (1.13.3-x86_64-linux)
      racc (~> 1.4)
    rake (13.0.6)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  rake

BUNDLED WITH
   2.3.7
`
	composer := `{
  "packages": [
    {"name": "laravel/framework", "version": "v10.0.0", "type": "library"},
    {"name": "psr/log", "version": "3.0.0"}
  ],
  "packages-dev": [
    {"name": "phpunit/phpunit", "version": "10.5.0"}
  ]
}`
	nugetLock := `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1", "contentHash": "abc"},
      "System.Text.Json": {"type": "Transitive", "resolved": "6.0.0"},
      "MyLib": {"type": "Project"}
    }
  }
}`
	depsJSON := `{
  "runtimeTarget": {"name": ".NETCoreApp,Version=v6.0"},
  "libraries": {
    "MyApp/1.0.0": {"type": "project", "serviceable": false, "sha512": ""},
    "Serilog/3.1.1": {"type": "package", "serviceable": true, "sha512": "sha512-abc", "path": "serilog/3.1.1"},
    "Microsoft.NETCore.App/6.0.0": {"type": "referenceassembly", "serviceable": false}
  }
}`
	by, pkgs, _ := run(t, map[string]string{
		"rust/Cargo.lock": cargo,
		"app.jar/META-INF/maven/org.apache.commons/commons-lang3/pom.properties": pom,
		"ruby/Gemfile.lock":              gemfile,
		"php/composer.lock":              composer,
		"dotnet/packages.lock.json":      nugetLock,
		"dotnet/bin/MyApp.deps.json":     depsJSON,
		"dotnet/bin/MyApp.runtimeconfig": "{}",
	})
	wantPURLs(t, pkgs,
		"pkg:cargo/myapp@0.1.0",
		"pkg:cargo/serde@1.0.197",
		"pkg:cargo/gitcrate@0.3.0",
		"pkg:maven/org.apache.commons/commons-lang3@3.12.0",
		"pkg:gem/gitgem@0.1.0",
		"pkg:gem/actioncable@7.0.4",
		"pkg:gem/nokogiri@1.13.3-x86_64-linux",
		"pkg:gem/rake@13.0.6",
		"pkg:composer/laravel/framework@v10.0.0",
		"pkg:composer/psr/log@3.0.0",
		"pkg:composer/phpunit/phpunit@10.5.0",
		"pkg:nuget/Newtonsoft.Json@13.0.1",
		"pkg:nuget/System.Text.Json@6.0.0",
		"pkg:nuget/Serilog@3.1.1",
	)
	if m := by["pkg:maven/org.apache.commons/commons-lang3@3.12.0"]; m.Namespace != "org.apache.commons" || m.Name != "commons-lang3" {
		t.Fatalf("maven = %+v", m)
	}
	if !by["pkg:composer/phpunit/phpunit@10.5.0"].Dev || !by["pkg:nuget/System.Text.Json@6.0.0"].Indirect {
		t.Fatalf("flags: %+v", pkgs)
	}
}

func TestDedupSources(t *testing.T) {
	files := map[string]string{}
	for _, dir := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		files[dir+"/go.mod"] = "module " + dir + "\nrequire example.com/mod v1.2.3\n"
	}
	files["x/go.mod"] = "module x\nrequire example.com/mod v1.2.3 // indirect\n"
	by, pkgs, _ := run(t, files)
	wantPURLs(t, pkgs, "pkg:golang/example.com/mod@v1.2.3")
	p := by["pkg:golang/example.com/mod@v1.2.3"]
	if p.Source != "a/go.mod;b/go.mod;c/go.mod;d/go.mod;e/go.mod" {
		t.Fatalf("source = %q", p.Source)
	}
	if p.Indirect {
		t.Fatal("direct requirement elsewhere should clear indirect")
	}

	// Same name/version but different arch or namespace stay distinct.
	_, pkgs, _ = run(t, map[string]string{
		"var/lib/dpkg/status": "Package: libc6\nStatus: install ok installed\nVersion: 2.41-12\nArchitecture: amd64\n\nPackage: libc6\nStatus: install ok installed\nVersion: 2.41-12\nArchitecture: i386\n",
	})
	wantPURLs(t, pkgs, "pkg:deb/debian/libc6@2.41-12?arch=amd64", "pkg:deb/debian/libc6@2.41-12?arch=i386")

	// Extra packages (Go binaries) are merged and deduplicated too.
	pkgs, _ = catalog(
		[]File{{Path: "go.mod", Data: []byte("module x\nrequire example.com/mod v1.2.3\n")}},
		[]Package{{Type: "golang", Name: "example.com/mod", Version: "v1.2.3", Source: "usr/bin/app"}, {Type: "golang", Name: "stdlib", Version: "1.22.4", Source: "usr/bin/app"}},
	)
	wantPURLs(t, pkgs, "pkg:golang/example.com/mod@v1.2.3", "pkg:golang/stdlib@1.22.4")
	if pkgs[0].Source != "go.mod;usr/bin/app" {
		t.Fatalf("merged source = %q", pkgs[0].Source)
	}
}

func TestGoBinaryPackages(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip("no executable:", err)
	}
	f, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	pkgs := goBinaryPackages(f, st.Size(), "usr/bin/scan.test", "sha256:layer")
	if len(pkgs) == 0 {
		t.Fatal("no packages from test binary")
	}
	found := false
	for _, p := range pkgs {
		if p.Type != "golang" || p.Source != "usr/bin/scan.test" || p.Layer != "sha256:layer" {
			t.Fatalf("package attribution wrong: %+v", p)
		}
		if p.Name == "stdlib" {
			found = true
			if p.Version == "" || strings.HasPrefix(p.Version, "go") {
				t.Fatalf("stdlib version = %q", p.Version)
			}
		}
		if p.Version == "(devel)" {
			t.Fatalf("(devel) version leaked: %+v", p)
		}
	}
	if !found {
		t.Fatalf("stdlib missing: %+v", pkgs)
	}
	// Through catalog the stdlib gets a purl and CPE.
	out, _ := catalog(nil, pkgs)
	for _, p := range out {
		if p.Name == "stdlib" && (!strings.HasPrefix(p.PURL, "pkg:golang/stdlib@") || !strings.HasPrefix(p.CPE, "cpe:2.3:a:golang:go:")) {
			t.Fatalf("stdlib purl/cpe = %q %q", p.PURL, p.CPE)
		}
	}

	t.Run("non-go input", func(t *testing.T) {
		if got := goBinaryPackages(strings.NewReader("#!/bin/sh\necho hi\n"), 17, "bin/sh", ""); got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
		if got := goBinaryPackages(nil, 10, "x", ""); got != nil {
			t.Fatal("nil reader should yield nil")
		}
		if got := goBinaryPackages(strings.NewReader(""), 0, "x", ""); got != nil {
			t.Fatal("empty reader should yield nil")
		}
	})
	t.Run("version normalization", func(t *testing.T) {
		for in, want := range map[string]string{"go1.22.4": "1.22.4", "go1.23rc1": "1.23rc1", "devel go1.24-abcdef Mon": "1.24", "": "", "weird": ""} {
			if got := goVersionNumber(in); got != want {
				t.Errorf("goVersionNumber(%q) = %q, want %q", in, got, want)
			}
		}
	})
}

func TestInteresting(t *testing.T) {
	yes := []string{
		"etc/os-release", "/etc/os-release", "usr/lib/os-release",
		"var/lib/dpkg/status", "/var/lib/dpkg/status", "var/lib/dpkg/status.d/libc6",
		"lib/apk/db/installed", "usr/lib/apk/db/installed",
		"app/package-lock.json", "app/node_modules/.package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"src/go.mod", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
		"x/PyYAML-6.0.1.dist-info/METADATA", "x/foo.egg-info/PKG-INFO", "x/legacy-1.0.egg-info",
		"Cargo.lock", "META-INF/maven/g/a/pom.properties", "Gemfile.lock", "composer.lock",
		"packages.lock.json", "bin/MyApp.deps.json",
	}
	no := []string{
		"var/lib/docker/overlay2/x/diff/etc/os-release", "home/u/testdata/os-release", "usr/share/os-release",
		"chroot/var/lib/dpkg/status", "var/lib/dpkg/status.d/libc6.md5sums", "var/lib/dpkg/status-old",
		"go.sum", "x/METADATA", "x/random/metadata", "x/foo.egg-info/requires.txt", "bin/MyApp.runtimeconfig.json",
		"docs/deps.json.md",
	}
	for _, p := range yes {
		if !interesting(p) {
			t.Errorf("interesting(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if interesting(p) {
			t.Errorf("interesting(%q) = true, want false", p)
		}
	}
}

func TestCatalogPreservesCaseSensitiveIdentities(t *testing.T) {
	for _, typ := range []string{"golang", "maven"} {
		pkgs, _ := catalog(nil, []Package{
			{Type: typ, Namespace: "example.com/Org", Name: "Pkg", Version: "v1.0.0"},
			{Type: typ, Namespace: "example.com/org", Name: "pkg", Version: "v1.0.0"},
		})
		if len(pkgs) != 2 {
			t.Errorf("%s: distinct identities merged: %+v", typ, pkgs)
		}
	}
	pkgs, _ := catalog(nil, []Package{
		{Type: "pypi", Name: "Some_Pkg", Version: "1.0"},
		{Type: "pypi", Name: "some-pkg", Version: "1.0"},
	})
	if len(pkgs) != 1 {
		t.Errorf("normalized PyPI identities not merged: %+v", pkgs)
	}
}
