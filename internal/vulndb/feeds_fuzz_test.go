package vulndb

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fuzzOSVRecord = `{"schema_version":"1.6.0","id":"GHSA-xxxx-yyyy-zzzz","modified":"2024-05-01T00:00:00Z","published":"2024-04-01T00:00:00Z","aliases":["CVE-2024-1234"," CVE-2024-1234 ","upstream"],"upstream":["CVE-2024-0001"],"related":["GHSA-aaaa-bbbb-cccc"],"summary":"Example summary","details":"Example details","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],"affected":[{"package":{"ecosystem":"npm","name":"lodash","purl":"pkg:npm/lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]},{"type":"GIT","repo":"https://github.com/lodash/lodash","events":[]}],"versions":["4.17.20"],"ecosystem_specific":{"binaries":[{"a":"1"}],"keep":true},"database_specific":{"source":"x"}},{"package":{"ecosystem":"Debian:bookworm","name":"node-lodash"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.21+dfsg-1"}]}]},{"package":{"ecosystem":"PyPI","purl":"pkg:pypi/Requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},{"package":{"ecosystem":"Go","name":"x","purl":"pkg:npm/y"}},{"package":{"ecosystem":"","name":"skip"}}],"references":[{"type":"WEB","url":"https://example.com/advisory"},{"type":"ADVISORY","url":"https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"}],"database_specific":{"cwe_ids":["CWE-79"],"severity":"HIGH"}}`

func fuzzCheckRecord(t *testing.T, r *Record) {
	t.Helper()
	if r == nil {
		return
	}
	if !validID(r.ID) {
		t.Fatalf("record with invalid id %q", r.ID)
	}
	if len(r.Details) > MaxDetails || len(r.Summary) > osvMaxSummary {
		t.Fatalf("record %s exceeds text bounds: details=%d summary=%d", r.ID, len(r.Details), len(r.Summary))
	}
	if len(r.Aliases) > osvMaxAliases || len(r.Related) > osvMaxAliases || len(r.References) > osvMaxReferences {
		t.Fatalf("record %s exceeds list bounds: %d aliases %d related %d refs", r.ID, len(r.Aliases), len(r.Related), len(r.References))
	}
	for _, a := range r.Affected {
		if strings.TrimSpace(a.Ecosystem) == "" || strings.TrimSpace(a.Package) == "" {
			t.Fatalf("record %s affected without ecosystem/package: %+v", r.ID, a)
		}
		for _, rg := range a.Ranges {
			if len(rg.Events) == 0 {
				t.Fatalf("record %s has an empty range", r.ID)
			}
		}
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatalf("record %s does not marshal: %v", r.ID, err)
	}
}

func fuzzZipFile(t *testing.T, members map[string][]byte) string {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "all.zip")
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func FuzzConvertOSV(f *testing.F) {
	f.Add([]byte(fuzzOSVRecord))
	f.Add([]byte(`{"id":"CVE-2024-0001","affected":[{"package":{"ecosystem":"Alpine:v3.20","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.3.1-r0"}]}]}]}`))
	f.Add([]byte(`{"id":"bad id","affected":[]}`))
	f.Add([]byte(`{"id":"CVE-2024-0002","affected":[{"package":{"ecosystem":"Debian:trixie","name":"a"},"versions":["1","2"],"severity":[{"type":"Ubuntu","score":"medium"}]}]}`))
	f.Add([]byte(`{"id":"CVE-2024-0003","details":"` + strings.Repeat("x", 70000) + `","affected":[{"package":{"ecosystem":"npm","name":"a"}}]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"id":"CVE-2024-0004","aliases":["` + strings.Repeat("A-", 100) + `"],"affected":[{"package":{"ecosystem":"npm","purl":"pkg:npm/%40scope/name"}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var v osvVuln
		if err := json.Unmarshal(data, &v); err != nil {
			return
		}
		rec, ok := ConvertOSV(&v, SourceOSV)
		if ok != (rec != nil) {
			t.Fatalf("ConvertOSV returned %v, %v", rec, ok)
		}
		fuzzCheckRecord(t, rec)
		if rec != nil && len(rec.Affected) == 0 {
			t.Fatalf("converted record without affected entries")
		}
		zipPath := fuzzZipFile(t, map[string][]byte{"a.json": data, "dir/": nil, "skip.txt": data})
		var emitted []*Record
		count, err := parseOSVZip(context.Background(), zipPath, SourceOSV, nil, func(r *Record) error {
			emitted = append(emitted, r)
			return nil
		}, nil)
		if err == nil && count != len(emitted) {
			t.Fatalf("parseOSVZip counted %d but emitted %d", count, len(emitted))
		}
		if err == nil && (rec != nil) != (len(emitted) == 1) {
			t.Fatalf("zip conversion emitted %d records, direct conversion ok=%v", len(emitted), rec != nil)
		}
		for _, r := range emitted {
			fuzzCheckRecord(t, r)
		}
	})
}

func FuzzAlpineSecDB(f *testing.F) {
	f.Add([]byte(`{"apkurl":"{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk","archs":["x86_64"],"distroversion":"v3.20","reponame":"main","urlprefix":"https://dl-cdn.alpinelinux.org/alpine","packages":[{"pkg":{"name":"openssl","secfixes":{"3.3.1-r0":["CVE-2024-4741","CVE-2024-4603 GHSL-2024-001"],"3.3.0-r2":["CVE-2024-2511"],"0":["CVE-2023-0000"],"3.1.4-r5_p1":["cve-2024-9999"]}}},{"pkg":{"name":"","secfixes":{"1":["CVE-1-1"]}}},{"pkg":{"name":"curl","secfixes":{"8.9.0-r0":["not an id","CVE-2024-6197 "],"":["CVE-2024-1"],"8.10.0-r0":[]}}}]}`))
	f.Add([]byte(`{"packages":[{"pkg":{"name":"a","secfixes":{"1.0-r0":["CVE-2024-0001"],"1.0-r1":["CVE-2024-0001"],"0.9":["CVE-2024-0001"]}}}]}`))
	f.Add([]byte(`{"packages":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "main.json")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		var last string
		err := parseAlpineSecDB(context.Background(), p, "v3.20", "main", func(r *Record) error {
			fuzzCheckRecord(t, r)
			if r.ID <= last {
				t.Fatalf("records not sorted: %q after %q", r.ID, last)
			}
			last = r.ID
			for _, a := range r.Affected {
				if !strings.HasPrefix(a.Ecosystem, "Alpine:") || !strings.HasPrefix(a.PURL, "pkg:apk/alpine/") {
					t.Fatalf("alpine affected %+v", a)
				}
			}
			return nil
		})
		_ = err
	})
}

func FuzzDebianTracker(f *testing.F) {
	f.Add([]byte(`{"openssl":{"CVE-2024-4741":{"description":"Use After Free with SSL_free_buffers","scope":"remote","releases":{"bookworm":{"status":"resolved","repositories":{"bookworm":"3.0.13-1~deb12u1"},"fixed_version":"3.0.14-1~deb12u1","urgency":"not yet assigned"},"trixie":{"status":"open","repositories":{"trixie":"3.2.1-3"},"urgency":"low","nodsa":"Minor issue","nodsa_reason":"postponed"},"sid":{"status":"resolved","fixed_version":"0"},"buster":{"status":"resolved","fixed_version":"undetermined"},"bullseye":{"status":"undetermined"},"":{"status":"open"}}},"not-an-id":{"releases":{"bookworm":{"status":"open"}}},"CVE-2024-0001":{"releases":{"bookworm":{"status":"open","fixed_version":"1.0"},"trixie":{"status":"resolved","fixed_version":"<unfixed>"}}}},"":{"CVE-2024-1":{"releases":{"bookworm":{"status":"open"}}}},"curl":{"CVE-2024-4741":{"description":"` + strings.Repeat("d", 70000) + `","releases":{"forky":{"status":"resolved","fixed_version":"8.9.0-1"}}}}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"pkg":{"CVE-2024-0001":{"releases":{"bookworm":{"status":"open"}}}}}{}`))
	f.Add([]byte(`{"pkg":[]}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "debian.json")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		var last string
		_ = parseDebianTracker(context.Background(), p, func(r *Record) error {
			fuzzCheckRecord(t, r)
			if r.ID <= last {
				t.Fatalf("records not sorted: %q after %q", r.ID, last)
			}
			last = r.ID
			for _, a := range r.Affected {
				if !strings.HasPrefix(a.Ecosystem, "Debian:") || len(a.Ranges) != 1 {
					t.Fatalf("debian affected %+v", a)
				}
				for _, e := range a.Ranges[0].Events {
					if e.Fixed == "0" || e.Fixed == "undetermined" || strings.HasPrefix(e.Fixed, "<") {
						t.Fatalf("debian affected with placeholder fix %+v", a)
					}
				}
			}
			return nil
		})
	})
}

func fuzzGzipFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func FuzzNVDFeed(f *testing.F) {
	f.Add([]byte(`{"resultsPerPage":1,"startIndex":0,"totalResults":1,"format":"NVD_CVE","version":"2.0","timestamp":"2024-05-01T00:00:00.000","vulnerabilities":[{"cve":{"id":"CVE-2024-1234","sourceIdentifier":"cve@mitre.org","published":"2024-04-01T10:15:00.000","lastModified":"2024-05-01T12:00:00.000","vulnStatus":"Analyzed","descriptions":[{"lang":"es","value":"hola"},{"lang":"en","value":"An issue was discovered."}],"metrics":{"cvssMetricV31":[{"source":"nvd@nist.gov","type":"Secondary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N","baseScore":5.3}},{"source":"nvd@nist.gov","type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8}}],"cvssMetricV2":[{"type":"Primary","cvssData":{"vectorString":"AV:N/AC:L/Au:N/C:P/I:P/A:P"}}]},"weaknesses":[],"references":[{"url":"https://example.com/1"},{"url":""},{"url":"https://example.com/2"},{"url":"https://example.com/3"},{"url":"https://example.com/4"},{"url":"https://example.com/5"},{"url":"https://example.com/6"}]}},{"cve":{"id":"CVE-2024-0002","published":"2024-04-01T10:15:00Z","lastModified":"bad","metrics":{"cvssMetricV40":[{"type":"Primary","cvssData":{"vectorString":" "}}]}}}]}`))
	f.Add([]byte(`{"vulnerabilities":[{"cve":{"id":"GHSA-not-cve"}}]}`))
	f.Add([]byte(`{"vulnerabilities":[],"vulnerabilities":[]}`))
	f.Add([]byte(`{"other":{"deep":[1,2,{"x":null}]}}`))
	f.Add([]byte(`{"vulnerabilities":[]} trailing`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := fuzzGzipFile(t, "nvdcve-2.0-2024.json.gz", data)
		_ = parseNVDFeed(context.Background(), p, func(r *Record) error {
			fuzzCheckRecord(t, r)
			if !strings.HasPrefix(r.ID, "CVE-") || r.Source != SourceNVD || len(r.References) > 5 {
				t.Fatalf("nvd record %+v", r)
			}
			return nil
		}, 1<<20)
		// A truncated gzip stream must surface as an error, never a panic.
		p2 := filepath.Join(t.TempDir(), "truncated.json.gz")
		raw, _ := os.ReadFile(p)
		if err := os.WriteFile(p2, raw[:len(raw)/2], 0o644); err != nil {
			t.Fatal(err)
		}
		_ = parseNVDFeed(context.Background(), p2, func(*Record) error { return nil }, 1<<20)
	})
}

func fuzzTar(entries []tar.Header, bodies [][]byte) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for i, h := range entries {
		if tw.WriteHeader(&h) != nil {
			continue
		}
		if i < len(bodies) && bodies[i] != nil {
			_, _ = tw.Write(bodies[i])
		}
	}
	_ = tw.Close()
	return b.Bytes()
}

func FuzzImportArchive(f *testing.F) {
	meta := []byte(`{"schema_version":2,"updated_at":"2024-05-01T00:00:00Z","sources":[],"ecosystems":[],"records":0}`)
	f.Add(fuzzTar([]tar.Header{
		{Name: "meta.json", Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(meta))},
		{Name: "cache/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "cache/npm.json.gz", Mode: 0o644, Typeflag: tar.TypeReg, Size: 3},
		{Name: "manifest.json", Mode: 0o644, Typeflag: tar.TypeReg, Size: 2},
	}, [][]byte{meta, nil, []byte("abc"), []byte("{}")}))
	f.Add(fuzzTar([]tar.Header{
		{Name: "../escape", Mode: 0o644, Typeflag: tar.TypeReg, Size: 1},
		{Name: "/absolute", Mode: 0o644, Typeflag: tar.TypeReg, Size: 1},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/tmp"},
		{Name: "dup", Mode: 0o644, Typeflag: tar.TypeReg, Size: 0},
		{Name: "dup", Mode: 0o644, Typeflag: tar.TypeReg, Size: 0},
		{Name: "dir/../x", Mode: 0o644, Typeflag: tar.TypeReg, Size: 0},
	}, [][]byte{{1}, {1}}))
	f.Add([]byte("not a tar at all"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		archive := fuzzGzipFile(t, "db.tar.gz", data)
		dir := filepath.Join(root, "db")
		_, err := importContextLimit(context.Background(), archive, dir, nil, 1<<20)
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "db.tmp-") {
				t.Fatalf("staging directory %s left behind after %v", name, err)
			}
		}
		if err == nil {
			t.Fatalf("import of fuzz archive succeeded without a verifiable database")
		}
		if _, statErr := os.Stat(dir); statErr == nil {
			t.Fatalf("failed import installed %s", dir)
		}
		// Uncompressed data straight through the reader path.
		raw := filepath.Join(root, "raw.tar")
		if err := os.WriteFile(raw, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = importContextLimit(context.Background(), raw, filepath.Join(root, "db2"), nil, 1<<20)
	})
}

func FuzzReadRecords(f *testing.F) {
	f.Add([]byte(`{"id":"CVE-2024-0001","affected":[{"ecosystem":"npm","package":"a","ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}],"source":"osv"}` + "\n" + `{"id":"CVE-2024-0002","affected":[],"source":"osv"}` + "\n"))
	f.Add([]byte("not json\n"))
	f.Add([]byte(strings.Repeat("x", 70000)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var gz bytes.Buffer
		w := gzip.NewWriter(&gz)
		_, _ = w.Write(data)
		_ = w.Close()
		_ = readRecordsBounded(bytes.NewReader(gz.Bytes()), func(r *Record) error {
			if _, err := json.Marshal(r); err != nil {
				t.Fatalf("record does not marshal: %v", err)
			}
			return nil
		}, 1<<20, 64<<10)
		// The same bytes as a raw (non-gzip) stream and as a zlib SQLite blob.
		_ = readRecordsBounded(bytes.NewReader(data), func(*Record) error { return nil }, 1<<20, 64<<10)
		var zb bytes.Buffer
		zw := zlib.NewWriter(&zb)
		_, _ = zw.Write(data)
		_ = zw.Close()
		var rec Record
		_ = decodeSQLiteRecordBounded(zb.Bytes(), &rec, 1<<20)
		_ = decodeSQLiteRecordBounded(data, &rec, 1<<20)
	})
}

func FuzzEcosystemNames(f *testing.F) {
	f.Add("Debian:13", "deb", "debian", "bookworm")
	f.Add("Ubuntu:Pro:24.04:LTS", "apk", "wolfi", "Ubuntu:jammy")
	f.Add("Alpine:v3.20", "PyPI", "", "sid")
	f.Add("", "Golang", "GitHub.com", "ubuntu-22.04")
	f.Fuzz(func(t *testing.T, eco, purlType, namespace, release string) {
		base := BaseEcosystem(eco)
		if strings.ContainsRune(base, ':') && strings.IndexByte(eco, ':') > 0 {
			t.Fatalf("BaseEcosystem(%q) = %q keeps a release", eco, base)
		}
		_ = EcosystemRelease(eco)
		_ = NormalizeName(eco, namespace)
		_ = PURLTypeToEcosystem(purlType, namespace)
		if r := NormalizeDebianRelease(release); r != strings.TrimSpace(r) {
			t.Fatalf("NormalizeDebianRelease(%q) = %q", release, r)
		}
		if r := NormalizeUbuntuRelease(release); r != strings.TrimSpace(r) {
			t.Fatalf("NormalizeUbuntuRelease(%q) = %q", release, r)
		}
		_ = alpineIssueID(release)
		_ = validID(eco)
		_ = safeName(eco)
		_ = safeRelative(release)
		_ = truncateText(release, 8)
	})
}
