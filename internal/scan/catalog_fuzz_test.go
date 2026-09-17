package scan

import (
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/purl"
)

// fuzzCatalogFile runs one metadata file through scanFile and the cataloger
// and checks the inventory invariants every parser must uphold: no panic,
// every retained package has a name, and its purl is parseable and keeps
// the package type.
func fuzzCatalogFile(t *testing.T, path string, data []byte) {
	t.Helper()
	var direct []Package
	scanFile(File{Path: path, Data: data}, func(p Package) { direct = append(direct, p) })
	pkgs, _ := catalog([]File{{Path: path, Data: data}}, nil)
	for _, p := range pkgs {
		if strings.TrimSpace(p.Name) == "" {
			t.Fatalf("%s: cataloged package without name: %+v", path, p)
		}
		if p.Type == "" {
			t.Fatalf("%s: cataloged package without type: %+v", path, p)
		}
		if p.PURL == "" {
			t.Fatalf("%s: cataloged package without purl: %+v", path, p)
		}
		parsed, err := purl.Parse(p.PURL)
		if err != nil {
			t.Fatalf("%s: purl %q does not parse: %v", path, p.PURL, err)
		}
		if parsed.Type != strings.ToLower(p.Type) {
			t.Fatalf("%s: purl %q type %q != package type %q", path, p.PURL, parsed.Type, p.Type)
		}
	}
	if len(direct) > 0 && len(pkgs) == 0 && len(data) > 0 {
		// Every direct discovery the cataloger would retain on its own must
		// survive cataloging of the file (the cataloger skips empty files
		// before dispatching them).
		for _, p := range direct {
			var c cataloger
			c.addPackage(p)
			if len(c.order) > 0 {
				t.Fatalf("%s: %d direct packages but catalog dropped all of them (%+v)", path, len(direct), p)
			}
		}
	}
}

func addSeeds(f *testing.F, seeds ...string) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
}

func FuzzScanDpkgStatus(f *testing.F) {
	addSeeds(f,
		"Package: curl\nStatus: install ok installed\nVersion: 8.14.1-2+deb13u3\nArchitecture: amd64\nSource: curl\n\nPackage: libssl3t64\nStatus: install ok installed\nVersion: 3.5.1-1\nArchitecture: amd64\nSource: openssl (3.5.1-1)\nDescription: SSL\n multi-line\n .\n more\n\n",
		"Package: gcc-14-base:amd64\nStatus: deinstall ok config-files\nVersion: 14.2.0-19\n\nPackage: broken\nStatus: install ok installed\n",
		"Package: nover\nStatus: install ok installed\nArchitecture: all\nSource: (1.0)\n\n",
		"Package: distroless\nVersion: 1.0\nArchitecture: amd64\n",
		"\r\nPackage: crlf\r\nStatus: install ok installed\r\nVersion: 1\r\n",
		": nokey\nPackage:\n\n\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "var/lib/dpkg/status", data)
		fuzzCatalogFile(t, "var/lib/dpkg/status.d/curl", data)
		var got []Package
		scanDpkgStatus(data, "status", "", func(p Package) { got = append(got, p) })
		for _, p := range got {
			if p.Name == "" || strings.ContainsRune(p.Name, ':') {
				t.Fatalf("dpkg package name %q not split from architecture", p.Name)
			}
		}
	})
}

func FuzzScanApkInstalled(f *testing.F) {
	addSeeds(f,
		"C:Q1abc\nP:musl\nV:1.2.5-r0\nA:x86_64\nS:1234\nI:5678\nT:the musl c library\nU:https://musl.libc.org/\nL:MIT\no:musl\nm:Timo\nt:1700000000\nc:abcdef\np:so:libc.musl-x86_64.so.1=1\nF:lib\nR:ld-musl-x86_64.so.1\na:0:0:755\nZ:Q1xyz\n\nP:curl\nV:8.9.0-r0\nA:x86_64\nL:curl\no:curl\n\n",
		"P:\nV:1\n\nX\n:\nP:noversion\n",
		"P:a\r\nV:1\r\n\r\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "lib/apk/db/installed", data)
		fuzzCatalogFile(t, "usr/lib/apk/db/installed", data)
		for _, e := range apkParagraphs(data) {
			for k := range e {
				if len(k) != 1 {
					t.Fatalf("apk key %q is not a single byte", k)
				}
			}
		}
	})
}

func FuzzParseOSRelease(f *testing.F) {
	addSeeds(f,
		"PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nVERSION=\"13 (trixie)\"\nVERSION_CODENAME=trixie\nID=debian\nHOME_URL=\"https://www.debian.org/\"\n",
		"NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n",
		"ID='ubuntu'\nID_LIKE=debian\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\n",
		"ID=\nVERSION_ID=1\n=\n===\n# comment\nID=Rocky\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		o := parseOSRelease(data)
		if o.ID != strings.ToLower(o.ID) {
			t.Fatalf("os-release ID %q not lowercased", o.ID)
		}
		for _, v := range []string{o.ID, o.IDLike, o.VersionID, o.Codename, o.PrettyName} {
			if strings.TrimSpace(v) != v {
				t.Fatalf("os-release value %q not trimmed: %+v", v, o)
			}
		}
		_ = o.Distro()
		files := []File{{Path: "etc/os-release", Data: data}, {Path: "usr/lib/os-release", Data: data}, {Path: "var/lib/dpkg/status", Data: []byte("Package: a\nVersion: 1\n")}}
		pkgs, osr := catalog(files, nil)
		if found := findOSRelease(files); (found == nil) != (osr == nil) {
			t.Fatalf("findOSRelease=%v catalog os=%v", found, osr)
		}
		for _, p := range pkgs {
			if _, err := purl.Parse(p.PURL); err != nil {
				t.Fatalf("purl %q: %v", p.PURL, err)
			}
		}
	})
}

func FuzzScanPackageLock(f *testing.F) {
	addSeeds(f,
		`{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/lodash":{"version":"4.17.21","license":"MIT"},"node_modules/@babel/core":{"version":"7.24.0","dev":true,"license":["MIT"]},"node_modules/link":{"link":true,"resolved":"../x"},"node_modules/git":{"version":"git+ssh://github.com/x/y.git"},"node_modules/a/node_modules/b":{"version":"1.0.0"}}}`,
		`{"lockfileVersion":2,"packages":{"node_modules/x":{"version":"1.2.3"}},"dependencies":{"x":{"version":"1.2.3"}}}`,
		`{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.21","dev":true,"dependencies":{"nested":{"version":"npm:real@2.0.0"},"file":{"version":"file:../local"}}},"@scope/pkg":{"version":"0.1.0"}}}`,
		`{"packages":{"":{}}}`, `[]`, `{"dependencies":{"a":{"dependencies":{"a":{"dependencies":{"a":{"version":"1"}}}}}}}`, ``, `{`,
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "app/package-lock.json", data)
		fuzzCatalogFile(t, "app/node_modules/.package-lock.json", data)
		fuzzCatalogFile(t, "npm-shrinkwrap.json", data)
	})
}

func FuzzScanInstalledNPM(f *testing.F) {
	addSeeds(f,
		`{"name":"lodash","version":"4.17.21","license":"MIT"}`,
		`{"name":"@babel/core","version":"7.24.0"}`,
		`{"name":"link","version":"1.0.0","link":true}`,
		`{"name":" ","version":"1"}`, `{"name":"x","version":"file:../y"}`, `null`, `[`,
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "app/node_modules/lodash/package.json", data)
		fuzzCatalogFile(t, "app/node_modules/@babel/core/package.json", data)
	})
}

func FuzzScanYarnLock(f *testing.F) {
	addSeeds(f,
		"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n\n\"@babel/code-frame@^7.0.0\", \"@babel/code-frame@^7.10.4\":\n  version \"7.24.2\"\n  resolved \"https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.2.tgz#123\"\n  integrity sha512-abc\n  dependencies:\n    \"@babel/highlight\" \"^7.24.2\"\n\nlodash@^4.17.21:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n",
		"# This file is generated by running \"yarn install\" inside your project.\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"@types/node@npm:^20.0.0\":\n  version: 20.11.0\n  resolution: \"@types/node@npm:20.11.0\"\n  checksum: 10c0/abc\n  languageName: node\n  linkType: hard\n\n\"alias@npm:real-name@^1.0.0\":\n  version: 1.2.3\n  resolution: \"real-name@npm:1.2.3\"\n\n\"my-app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"my-app@workspace:.\"\n\n\"patched@patch:patched@npm%3A1.0.0#./.yarn/patches/x.patch\":\n  version: 1.0.0\n",
		"x@1:\n\tversion \"1\"\n\n@:\n  version: \n  resolution: \"@npm:\"\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "yarn.lock", data)
	})
}

func FuzzScanPnpmLock(f *testing.F) {
	addSeeds(f,
		"lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.21\n        version: 4.17.21\n\npackages:\n\n  '@babel/core@7.24.0':\n    resolution: {integrity: sha512-abc}\n    engines: {node: '>=6.9.0'}\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-def}\n\n  react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: sha512-ghi}\n    peerDependencies:\n      react: ^18.2.0\n\nsnapshots:\n\n  lodash@4.17.21: {}\n",
		"lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-abc}\n    dev: false\n\n  /@types/node/20.0.0_typescript@5.0.0:\n    resolution: {integrity: sha512-def}\n    dev: true\n",
		"lockfileVersion: 6.0\npackages:\n  /lodash@4.17.21:\n    dev: true\n  '@':\n  x:\n    dev: true\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "pnpm-lock.yaml", data)
	})
}

func FuzzScanGoMod(f *testing.F) {
	addSeeds(f,
		"module github.com/ziozzang/bongsu-scanner\n\ngo 1.25.0\n\ntoolchain go1.27.1\n\nrequire (\n\tgithub.com/klauspost/compress v1.20.0\n\tgolang.org/x/sys v0.47.0 // indirect\n\tmodernc.org/sqlite v1.58.0\n)\n\nrequire github.com/x/y v1.0.0\n\nreplace github.com/x/y => github.com/z/y v1.1.0\n\nreplace github.com/x/y v1.0.0 => ../local\n\nexclude golang.org/x/sys v0.1.0\n\nretract (\n\tv1.0.0\n\t[v1.1.0, v1.2.0]\n)\n",
		"module \"quoted/mod\"\nrequire \"github.com/a/b\" `v1.0.0`\nreplace (\n\ta => b\n\tc v1 => d v2\n\t=> x\n)\nexclude (\n\ta\n)\n",
		"require (\n// comment\n\tgithub.com/a/b v1.0.0 //indirect\n",
		"replace a => \"bad\\q\"\nrequire ( x\n)\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "src/go.mod", data)
	})
}

func FuzzScanRequirements(f *testing.F) {
	addSeeds(f,
		"# deps\n-i https://pypi.org/simple\n--extra-index-url https://x\nrequests==2.31.0 \\\n    --hash=sha256:abc \\\n    --hash=sha256:def\nDjango>=4.2,<5.0\nnumpy===1.26.4 ; python_version >= \"3.9\"\nPyYAML[safe]==6.0.1  # inline comment\ncelery (==5.3.0)\n-e git+https://github.com/x/y.git#egg=y\ngit+https://github.com/a/b\n./local\n/abs/path\nhttps://example.com/pkg.whl\npkg @ https://example.com/pkg.whl\nflask==2.*\n--find-links ./wheels\nuv==0.1.0 --no-binary :all:\n",
		"a[b==1\nb[\n==\n(==1)\n\\\n\\\nc===\n[x]==1\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "requirements.txt", data)
	})
}

func FuzzScanPythonMetadata(f *testing.F) {
	addSeeds(f,
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nSummary: Python HTTP for Humans.\nHome-page: https://requests.readthedocs.io\nLicense: Apache 2.0\nClassifier: License :: OSI Approved :: Apache Software License\nRequires-Dist: charset-normalizer (<4,>=2)\n\nRequests is an HTTP library.\n",
		"Metadata-Version: 2.4\nName: Zope.Interface_Foo\nVersion: 1.0\nLicense-Expression: MIT\nLicense: UNKNOWN\n",
		"Name: x\nVersion:\n 1.0\n",
		"\nName: after-blank\nVersion: 1\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA", data)
		fuzzCatalogFile(t, "lib/python3.11/site-packages/x.egg-info/PKG-INFO", data)
		fuzzCatalogFile(t, "site-packages/single.egg-info", data)
	})
}

func FuzzScanTOMLLock(f *testing.F) {
	addSeeds(f,
		"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"abc\"\ndependencies = [\n \"serde_derive\",\n]\n\n[[package]]\nname = \"serde_derive\"\nversion = \"1.0.197\"\n\n[[patch.unused]]\nname = \"unused\"\nversion = \"0.1.0\"\n",
		"[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\ndescription = \"Python HTTP for Humans.\"\ncategory = \"main\"\noptional = false\npython-versions = \">=3.7\"\n\n[package.dependencies]\ncertifi = \">=2017.4.17\"\n\n[[package]]\nname = \"pytest\"\nversion = \"8.0.0\"\ncategory = \"dev\"\n\n[metadata]\nlock-version = \"2.0\"\n",
		"version = 1\nrevision = 1\nrequires-python = \">=3.12\"\n\n[[package]]\nname = \"my-app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\ndependencies = [\n    { name = \"requests\" },\n]\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\nsource = { registry = \"https://pypi.org/simple\" }\ndescription = \"\"\"\nmulti\n[[package]]\nline\n\"\"\"\n\n[[package]]\nname = 'single'\nversion = '1.0'\nnote = '''raw\n'''\n",
		"[[package]]\nname = \"a\\\"b\"\nversion = \"1\" # comment\n[[package]]\nname=\"\"\"x\"\"\"\nversion=\"\"\"\n\"\"\"\"\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "Cargo.lock", data)
		fuzzCatalogFile(t, "poetry.lock", data)
		fuzzCatalogFile(t, "uv.lock", data)
		for _, e := range tomlPackages(string(data)) {
			for k := range e {
				if strings.TrimSpace(k) != k {
					t.Fatalf("toml key %q not trimmed", k)
				}
			}
		}
	})
}

func FuzzScanPipfileLock(f *testing.F) {
	addSeeds(f,
		`{"_meta":{"hash":{"sha256":"abc"},"pipfile-spec":6},"default":{"requests":{"hashes":["sha256:x"],"index":"pypi","version":"==2.31.0"},"Django":{"version":"==4.2"}},"develop":{"pytest":{"version":"==8.0.0"},"nover":{}}}`,
		`{"default":null,"develop":{"a":{"version":"=="}}}`, `{"default":[]}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "Pipfile.lock", data)
	})
}

func FuzzScanPomProperties(f *testing.F) {
	addSeeds(f,
		"#Generated by Maven\n#Mon Jan 01 00:00:00 UTC 2024\nversion=3.12.0\ngroupId=org.apache.commons\nartifactId=commons-lang3\n",
		"artifactId=a b\nversion==1\ngroupId=\n=x\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "META-INF/maven/org.apache.commons/commons-lang3/pom.properties", data)
		v := keyValues(data, "=")
		for k := range v {
			if k == "" {
				t.Fatalf("keyValues produced an empty key")
			}
		}
	})
}

func FuzzScanGemfileLock(f *testing.F) {
	addSeeds(f,
		"GEM\n  remote: https://rubygems.org/\n  specs:\n    actionpack (7.0.4)\n      activesupport (= 7.0.4)\n      rack (~> 2.0, >= 2.2.0)\n    rails (7.0.4)\n    nokogiri (1.15.4-x86_64-linux)\n      racc (~> 1.4)\n\nPLATFORMS\n  x86_64-linux\n\nDEPENDENCIES\n  rails (~> 7.0)\n\nBUNDLED WITH\n   2.4.10\n",
		"GIT\n  remote: https://github.com/x/y.git\n  revision: abc\n  specs:\n    y (0.1.0)\n\nPATH\n  remote: .\n  specs:\n    local (1.0.0)\n",
		"  specs:\n    (1)\n    name (\n    name)\n     deeper (1)\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "Gemfile.lock", data)
	})
}

func FuzzScanGemspec(f *testing.F) {
	addSeeds(f,
		"# -*- encoding: utf-8 -*-\n# stub: rake 13.0.6 ruby lib\n\nGem::Specification.new do |s|\n  s.name = \"rake\".freeze\n  s.version = \"13.0.6\"\n\n  s.required_rubygems_version = Gem::Requirement.new(\">= 0\".freeze) if s.respond_to? :required_rubygems_version=\n  s.authors = [\"Hiroshi SHIBATA\".freeze]\nend\n",
		"Gem::Specification.new do |spec|\n  spec.name    = 'json'\n  spec.version = Gem::Version.new('2.7.1')\nend\n",
		"s.name=\"\"\ns.version = \"1\n",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "usr/lib/ruby/gems/3.2.0/specifications/rake-13.0.6.gemspec", data)
		fuzzCatalogFile(t, "usr/lib/ruby/gems/3.2.0/specifications/default/json-2.7.1.gemspec", data)
	})
}

func FuzzScanComposerLock(f *testing.F) {
	addSeeds(f,
		`{"_readme":["x"],"content-hash":"abc","packages":[{"name":"laravel/framework","version":"v10.0.0","source":{"type":"git"}},{"name":"psr/log","version":"3.0.0"},{"name":"noversion"},{"version":"1"}],"packages-dev":[{"name":"phpunit/phpunit","version":"10.5.0"}],"minimum-stability":"stable"}`,
		`{"packages":[{"name":"/","version":"1"},{"name":"a/","version":"1"},{"name":"/b","version":"1"}]}`,
		`{"packages":{}}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "composer.lock", data)
	})
}

func FuzzScanNuGet(f *testing.F) {
	addSeeds(f,
		`{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1","contentHash":"abc"},"System.Text.Json":{"type":"Transitive","resolved":"8.0.0"},"MyProject":{"type":"Project"},"NoResolved":{"type":"Direct"}},"net8.0/linux-x64":{"runtime.linux-x64.Microsoft.NETCore.App":{"type":"Transitive","resolved":"8.0.0"}}}}`,
		`{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0"},"targets":{".NETCoreApp,Version=v8.0":{"Newtonsoft.Json/13.0.1":{"runtime":{"lib/net6.0/Newtonsoft.Json.dll":{}}}}},"libraries":{"Newtonsoft.Json/13.0.1":{"type":"package","serviceable":true,"sha512":"sha512-abc","path":"newtonsoft.json/13.0.1"},"MyApp/1.0.0":{"type":"project","serviceable":false},"NoSlash":{"type":"package"},"Trailing/":{"type":"package"},"/1.0":{}}}`,
		`{"dependencies":{"a":null}}`, `{"libraries":null}`,
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzCatalogFile(t, "obj/packages.lock.json", data)
		fuzzCatalogFile(t, "bin/MyApp.deps.json", data)
	})
}

func FuzzParagraphs(f *testing.F) {
	addSeeds(f,
		"Key: value\n cont\n\tmore\nOther: x\n\nSecond: 1\n",
		" leading continuation\nNoColon\n:empty\nK:\n\n\n",
		"A: 1\r\nB: 2\r\n\r\nC: 3",
	)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, para := range paragraphs(data) {
			if len(para) == 0 {
				t.Fatalf("paragraphs emitted an empty paragraph")
			}
			for k := range para {
				if k == "" || strings.ContainsRune(k, ':') {
					t.Fatalf("paragraph key %q", k)
				}
			}
		}
	})
}
