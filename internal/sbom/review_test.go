package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func TestSPDXCommentJSONKey(t *testing.T) {
	r := fixture()
	r.Host = &scan.HostMetadata{Hostname: "test-host"}
	_, raw := mustSPDX(t, r)
	var doc struct {
		Packages []map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Packages {
		if _, exists := p["packageComment"]; exists {
			t.Errorf("invalid packageComment key in %s", p["SPDXID"])
		}
	}
	for _, i := range []int{0, 1, 2} { // Host, OS and package metadata.
		if len(doc.Packages[i]["comment"]) == 0 {
			t.Errorf("package %d missing comment", i)
		}
	}
}

// Download https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json
// to /tmp/spdx-schema.json to enable this offline schema-key check.
func TestSPDXKeysMatchOfficialSchema(t *testing.T) {
	b, err := os.ReadFile("/tmp/spdx-schema.json")
	if os.IsNotExist(err) {
		t.Skip("official SPDX schema absent: /tmp/spdx-schema.json")
	}
	if err != nil {
		t.Fatal(err)
	}
	type schemaNode struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Items      json.RawMessage            `json:"items"`
	}
	var check func(reflect.Type, json.RawMessage, string)
	check = func(typ reflect.Type, raw json.RawMessage, path string) {
		var schema schemaNode
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if typ.Kind() == reflect.Slice {
			check(typ.Elem(), schema.Items, path+"[]")
			return
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			child, ok := schema.Properties[key]
			if !ok {
				t.Errorf("%s.%s is absent from the official schema", path, key)
				continue
			}
			check(field.Type, child, path+"."+key)
		}
	}
	check(reflect.TypeFor[spdxDoc](), b, "document")
}

func TestLicenseExpressionLimits(t *testing.T) {
	for name, input := range map[string]string{
		"bytes":      strings.Repeat(" ", 4094) + "MIT",
		"tokens":     strings.Repeat("(", 256) + "MIT" + strings.Repeat(")", 256),
		"long chain": strings.Repeat("MIT OR ", 16000) + "MIT",
	} {
		t.Run(name, func(t *testing.T) {
			if out, ok := licenseExpression(input); ok || out != "" {
				t.Errorf("over-limit expression accepted (%d bytes)", len(input))
			}
			want := firstLine(input, 200)
			licenses := cdxLicenses(input)
			if len(licenses) != 1 || licenses[0].Expression != "" || licenses[0].License == nil || licenses[0].License.Name != want {
				t.Error("CycloneDX did not preserve capped free-form license name")
			}
			pkg := spdxPackageFor(scan.Package{Name: "test", License: input}, "SPDXRef-test")
			if pkg.LicenseDeclared != noAssert || pkg.LicenseComments != "declared license text is not an SPDX expression: "+want {
				t.Error("SPDX did not preserve capped free-form license text")
			}
		})
	}
	for _, input := range []string{
		strings.Repeat(" ", 4093) + "MIT",
		strings.Repeat("(", 255) + "MIT" + strings.Repeat(")", 255),
		strings.Repeat("MIT or ", 255) + "mit",
	} {
		out, ok := licenseExpression(input)
		want := strings.ReplaceAll(strings.TrimSpace(input), "or", "OR")
		want = strings.ReplaceAll(want, "mit", "MIT")
		if !ok || out != want {
			t.Errorf("valid expression below limits rejected or changed (%d bytes)", len(input))
		}
	}
}

func TestDocumentIdentifiersCoverPackageContentAndBuild(t *testing.T) {
	base := fixture()
	baseCDX, _ := mustCDX(t, base)
	baseSPDX, _ := mustSPDX(t, base)
	for name, mutate := range map[string]func(*scan.Result){
		"type":           func(r *scan.Result) { r.Packages[0].Type += "x" },
		"namespace":      func(r *scan.Result) { r.Packages[0].Namespace += "x" },
		"name":           func(r *scan.Result) { r.Packages[0].Name += "x" },
		"version":        func(r *scan.Result) { r.Packages[0].Version += "x" },
		"purl":           func(r *scan.Result) { r.Packages[0].PURL += "x" },
		"last package":   func(r *scan.Result) { r.Packages[len(r.Packages)-1].Name += "x" },
		"add package":    func(r *scan.Result) { r.Packages = append(r.Packages, r.Packages[0]) },
		"remove package": func(r *scan.Result) { r.Packages = r.Packages[1:] },
		"source type":    func(r *scan.Result) { r.SourceType = "directory" },
		"tool version": func(r *scan.Result) {
			ToolVersion += "-test"
		},
	} {
		t.Run(name, func(t *testing.T) {
			old := ToolVersion
			t.Cleanup(func() { ToolVersion = old })
			r := fixture()
			mutate(&r)
			cdx, _ := mustCDX(t, r)
			spdx, _ := mustSPDX(t, r)
			if cdx.Serial == baseCDX.Serial || spdx.DocumentNamespace == baseSPDX.DocumentNamespace {
				t.Error("changed content reused a document identifier")
			}
		})
	}
}

// SBOM_FIXTURE_DIR optionally retains regenerated fixtures for external validation.
func TestRegenerateFixtures(t *testing.T) {
	dir := os.Getenv("SBOM_FIXTURE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"spdx", "cyclonedx"} {
		if err := Write(filepath.Join(dir, "fixture."+format+".json"), format, fixture()); err != nil {
			t.Fatal(err)
		}
	}
}
