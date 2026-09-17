package match

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/assessment"
)

func streamFixtureFile(t testing.TB, input string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(input), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSBOMStreamMatchesLegacy(t *testing.T) {
	fixtures := []string{
		`{"unknown":[{"deep":[null,true,1.25,"<>\u2028"]}],"metadata":{"component":{"name":"root","properties":[{"name":"bscan:host:operating-system","value":"debian"},{"name":"bscan:host:os-version","value":"13"},{"name":"bscan:host:architecture","value":"amd64"},{"name":"bscan:image:architecture","value":"arm64"},{"name":"bscan:image:os","value":"linux"}],"components":[{"name":"root-child"}]}},"components":[{"components":[{"name":"nested","purl":"pkg:deb/debian/test@1","properties":[{"name":"bscan:upstream","value":"source@2"}]}],"name":"parent","group":"custom","unknown":{"n":9007199254740993}},{"type":"operating-system","name":"debian","version":"13","properties":[{"name":"bscan:os:codename","value":"trixie"}]}],"signature":{"value":"obsolete"},"vulnerabilities":[{"id":"old"}],"bomFormat":"CycloneDX","specVersion":"1.4","version":9}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":2,"Name":"ignored","version":null,"properties":[null,{"name":"duplicate","value":"old"},{"name":"duplicate","value":true}],"components":[{"name":"discard"}],"components":[{"name":"keep"}]}],"metadata":{"component":false}}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"discard"}],"components":[{"bom-ref":"x","purl":"pkg:deb/ubuntu/x@1","properties":[{"name":"bscan:distro","value":"ubuntu-jammy"}]}],"metadata":{"component":{"name":"discard"}},"metadata":{"component":{"type":"operating-system","name":"ubuntu","version":"22.04"}}}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"operating-system","name":"ubuntu","version":"24.04"},{"type":"operating-system","name":"debian","version":"13"},{"purl":"pkg:deb/debian/x@1"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"properties":[{"name":"bscan:host:operating-system","value":"debian"}]}},"components":[{"type":"operating-system","name":"ubuntu","version":"24.04"},{"purl":"pkg:deb/debian/x@1"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[],"metadata":{"component":null}}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-Root","name":"root","packageComment":"bscan host metadata: {\"operating_system\":\"debian\",\"os_version\":\"13\",\"architecture\":\"amd64\"}","annotations":[{"comment":"bscan image metadata: {\"operating_system\":\"linux\",\"architecture\":\"arm64\"}"}]},{"SPDXID":"os","primaryPackagePurpose":"OPERATING-SYSTEM","name":"debian","versionInfo":"13"},{"SPDXID":"pkg","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:deb/debian/x@1"},{"referenceType":"other","referenceLocator":"ignored"}],"properties":[{"name":"bscan:upstream","value":"source@2"}]}]}`,
		`{"spdxVersion":"SPDX-2.2","packages":[{"name":"x","purl":"pkg:pypi/fallback@1","externalRefs":[]},{"name":"y","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/override@2"}],"purl":"pkg:pypi/ignored@1"}]}`,
		`{"spdxVersion":"SPDX-2.3","packages":[{"name":"root","annotations":[{"comment":"bscan image metadata: {\"operating_system\":\"linux\",\"architecture\":\"arm64\"}"}]}]}`,
	}
	for i, input := range fixtures {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			want, err := loadCompactFile([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			got, err := LoadFile(streamFixtureFile(t, input))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Subjects, want.Subjects) || !reflect.DeepEqual(got.Context, want.Context) || got.Format != want.Format {
				t.Fatalf("inventory diff (-old +new):\n-%+v / %+v\n+%+v / %+v", want.Subjects, want.Context, got.Subjects, got.Context)
			}
			a, b := assessmentEnvironment(want, assessment.Environment{}), assessmentEnvironment(got, assessment.Environment{})
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("environment diff:\n-%+v\n+%+v", a, b)
			}
			report := Report{GeneratedAt: time.Unix(0, 0), Subjects: len(want.Subjects)}
			if len(want.Subjects) > 0 {
				report.Findings = []Finding{{ID: "CVE-fixture", Subject: want.Subjects[0]}}
			}
			for _, format := range []string{"table", "json", "cyclonedx"} {
				var before, after bytes.Buffer
				if err := Write(&before, format, report, want); err != nil {
					t.Fatal(err)
				}
				if err := Write(&after, format, report, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before.Bytes(), after.Bytes()) {
					t.Fatalf("%s byte diff:\n-%s\n+%s", format, before.Bytes(), after.Bytes())
				}
			}
		})
	}
}

func TestSBOMStreamValidation(t *testing.T) {
	fixtures := []string{
		`{"bomFormat":"CycloneDX","specVersion":"9","components":[]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"bom-ref":"same"},{"bom-ref":"same"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{}, {"bom-ref":"bscan-subject-1"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"bom-ref":"same"}},"components":[{"bom-ref":"same"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"purl":"invalid"}]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","unknown":1e1000}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","unknown":[1,]}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6"} {}`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6"`,
		`{"spdxVersion":"SPDX-2.4"}`, `[]`, `null`,
		`{"bomFormat":"CycloneDX","specVersion":"1.6","unknown":` + strings.Repeat("[", 10001) + `0` + strings.Repeat("]", 10001) + `}`,
	}
	for i, input := range fixtures {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := Load([]byte(input)); err == nil {
				t.Fatal("invalid legacy fixture")
			}
			if _, err := LoadFile(streamFixtureFile(t, input)); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}

func TestSBOMStreamRejectsChangedSource(t *testing.T) {
	path := streamFixtureFile(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`)
	d, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"changed"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Write(&output, "cyclonedx", Report{}, d); err == nil || output.Len() != 0 {
		t.Fatalf("changed source not rejected before writing: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Write(&output, "cyclonedx", Report{}, d); err == nil {
		t.Fatal("missing source accepted")
	}
	if err := Write(&output, "json", Report{}, d); err != nil {
		t.Fatal(err)
	}
}

func generatedStreamFixture(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "50k.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[`)
	for i := 0; i < 50000; i++ {
		if i > 0 {
			out.WriteByte(',')
		}
		fmt.Fprintf(&out, `{"bom-ref":"ref-%d","type":"library","name":"package-%d","version":"1","purl":"pkg:npm/package-%d@1","properties":[{"name":"bscan:source","value":"/fixture/package-%d"}],"unknown":{"hashes":["%s"]}}`, i, i, i, i, strings.Repeat("a", 256))
	}
	out.WriteString(`]}`)
	if _, err := out.WriteTo(f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSBOMStream50KAllocationBound(t *testing.T) {
	if testing.Short() {
		t.Skip("50k allocation regression")
	}
	path := generatedStreamFixture(t)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	d, err := LoadFile(path)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Subjects) != 50000 {
		t.Fatalf("subjects=%d", len(d.Subjects))
	}
	if d.Raw["components"] != nil {
		t.Fatal("retained full components")
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("allocated=%d bytes mallocs=%d", allocated, after.Mallocs-before.Mallocs)
	// Go 1.25 Token allocates more than the Go 1.27 implementation. Keep
	// portable ceilings; benchmarks report the tighter toolchain-specific cost.
	if allocated > 192<<20 {
		t.Fatalf("50k loader allocated %d bytes, limit 192 MiB", allocated)
	}
	if mallocs := after.Mallocs - before.Mallocs; mallocs > 7000000 {
		t.Fatalf("50k loader made %d allocations, limit 7000000", mallocs)
	}
	runtime.KeepAlive(d)
}

func BenchmarkSBOMStream50K(b *testing.B) {
	path := generatedStreamFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d, err := LoadFile(path)
		if err != nil {
			b.Fatal(err)
		}
		if len(d.Subjects) != 50000 {
			b.Fatal(len(d.Subjects))
		}
	}
}

// Optional semantic inventory snapshot used for diffing real-workload binaries.
func TestLoaderInventorySnapshot(t *testing.T) {
	input, output := os.Getenv("MATCH_PROFILE_SBOM"), os.Getenv("MATCH_INVENTORY_OUTPUT")
	if input == "" || output == "" {
		t.Skip("set MATCH_PROFILE_SBOM and MATCH_INVENTORY_OUTPUT")
	}
	d, err := LoadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(struct {
		Subjects []Subject
		Context  Context
	}{d.Subjects, d.Context}); err != nil {
		t.Fatal(err)
	}
}

func TestSBOMStreamRejectsNonObjectComponent(t *testing.T) {
	// The editable legacy loader panics when inserting a generated ref into
	// these entries. Reject them during loading, before delayed output can panic.
	for _, value := range []string{"null", "true", "1", `"text"`, "[]"} {
		input := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` + value + `]}`
		if _, err := LoadFile(streamFixtureFile(t, input)); err == nil {
			t.Fatalf("accepted %s component", value)
		}
	}
}

func TestSBOMStreamPropertiesRemainIndependent(t *testing.T) {
	d, err := LoadFile(streamFixtureFile(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"a","properties":[{"name":"same","value":"original"}]},{"name":"b","properties":[{"name":"same","value":"original"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	d.Subjects[0].Properties["same"] = "changed"
	if d.Subjects[1].Properties["same"] != "original" {
		t.Fatal("interning shared mutable maps")
	}
}
