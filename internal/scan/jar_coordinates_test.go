package scan

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func packageJSONField(t *testing.T, p Package, key string) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	v, _ := fields[key].(string)
	return v
}

func TestJavaCoordinateDerivation(t *testing.T) {
	for _, tc := range []struct {
		name, manifest, classes, want, evidence string
	}{
		{"catalina.jar", "Implementation-Title: Apache Tomcat\nImplementation-Version: 10.1.60\n", "", "pkg:generic/catalina@10.1.60", "manifest"},
		{"catalina.jar", "Implementation-Title: Apache Tomcat\nBundle-SymbolicName: org.apache.tomcat-catalina\nImplementation-Version: 10.1.60\n", "org/apache/catalina/A.class", "pkg:maven/org.apache.tomcat/tomcat-catalina@10.1.60", "manifest"},
		{"catalina-tribes.jar", "Bundle-SymbolicName: org.apache.tomcat-tribes\nBundle-Version: 10.1.60\n", "", "pkg:maven/org.apache.tomcat/tomcat-tribes@10.1.60", "manifest"},
		{"tomcat-util.jar", "Bundle-SymbolicName: org.apache.tomcat-util\nBundle-Version: 10.1.60\n", "", "pkg:maven/org.apache.tomcat/tomcat-util@10.1.60", "manifest"},
		{"catalina.jar", "Implementation-Title: Apache Tomcat\nImplementation-Version: 10.1.60\n", "org/apache/catalina/A.class", "pkg:maven/org.apache.tomcat/tomcat-catalina@10.1.60", "manifest"},
		{"tomcat-embed-core-10.1.60.jar", "Implementation-Title: Apache Tomcat\nImplementation-Vendor-Id: org.apache.tomcat.embed\nImplementation-Version: 10.1.60\n", "", "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.60", "manifest"},
		{"lib-1.0.jar", "Implementation-Vendor-Id: The Vendor\nBundle-SymbolicName: org.example.lib;singleton:=true\nBundle-Version: 2.0\n", "", "pkg:maven/org.example/lib@2.0", "manifest"},
		{"lib.jar", "Automatic-Module-Name: com.acme.lib\nSpecification-Version: 3.0\n", "", "pkg:maven/com.acme/lib@3.0", "manifest"},
		{"lib.jar", "Bundle-SymbolicName: com.acme.lib-core\nBundle-Version: 3.0\n", "", "pkg:maven/com.acme/lib@3.0", "manifest"},
		{"lib.jar", "Implementation-Version: 4.0\nImplementation-Vendor-Id: org.acme\nBundle-SymbolicName: com.other.lib\n", "", "pkg:maven/org.acme/lib@4.0", "manifest"},
		{"lib-1.0.jar", "Implementation-Version: 4.0\nBundle-Version: 5.0\nSpecification-Version: 6.0\n", "", "pkg:generic/lib@4.0", "manifest"},
		{"lib-1.0.jar", "Implementation-Vendor-Id: org.acme\n", "", "pkg:maven/org.acme/lib@1.0", "manifest"},
		{"lib-1.0.jar", "Implementation-Title: Human Title\n", "", "pkg:generic/lib@1.0", "filename"},
		{"lib-1.0-RC1.jar", "", "", "pkg:generic/lib@1.0-RC1", "filename"},
		{"lib-1.0.jar", "", "org/example/lib/A.class,org/example/lib/B.class,com/other/C.class", "pkg:maven/org.example.lib/lib@1.0", "filename"},
		{"lib-1.0.jar", "", "com/zeta/Z.class,com/alpha/A.class", "pkg:maven/com.alpha/lib@1.0", "filename"},
		{"lib-1.0.jar", "Implementation-Vendor-Id: Apache Tomcat\nAutomatic-Module-Name: no spaces.allowed\n", "local/A.class", "pkg:generic/lib@1.0", "filename"},
	} {
		t.Run(tc.name+"/"+tc.want, func(t *testing.T) {
			entries := map[string][]byte{}
			if tc.manifest != "" {
				entries["META-INF/MANIFEST.MF"] = []byte(tc.manifest)
			}
			if tc.classes != "" {
				for _, name := range strings.Split(tc.classes, ",") {
					entries[name] = nil
				}
			}
			pkgs, _ := catalog([]File{{Path: tc.name, Data: gapZIP(t, entries)}}, nil)
			if len(pkgs) != 1 || pkgs[0].PURL != tc.want {
				t.Fatalf("packages = %+v; want %s", pkgs, tc.want)
			}
			if got := packageJSONField(t, pkgs[0], "evidence"); got != "installed" {
				t.Errorf("evidence = %q; want %q", got, "installed")
			}
		})
	}
}

func TestJavaRejectsSpaceCoordinates(t *testing.T) {
	data := gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Implementation-Version: 1\n")})
	pkgs, _ := catalog([]File{{Path: "Human Title.jar", Data: data}}, nil)
	if len(pkgs) != 0 {
		t.Fatalf("packages = %+v", pkgs)
	}
}

func TestJavaArchiveRelease(t *testing.T) {
	for _, vendor := range []string{"OpenJDK", "Oracle Corporation", "Eclipse Adoptium"} {
		t.Run(vendor, func(t *testing.T) {
			data := gapZIP(t, map[string][]byte{"jre/release": []byte("JAVA_VERSION=\"17.0.20\"\nIMPLEMENTOR=\"" + vendor + "\"\n")})
			pkgs, _ := catalog([]File{{Path: "runtime.jar", Data: data}}, nil)
			if len(pkgs) != 1 || pkgs[0].Type != "generic" || pkgs[0].Version != "17.0.20" || pkgs[0].Evidence != "installed" {
				t.Fatalf("packages = %+v", pkgs)
			}
			wantName, wantCPE := "openjdk", "cpe:2.3:a:oracle:openjdk:17.0.20:*:*:*:*:*:*:*"
			if vendor == "Eclipse Adoptium" {
				wantName, wantCPE = "java-runtime", ""
			}
			if pkgs[0].Name != wantName || pkgs[0].CPE != wantCPE {
				t.Fatalf("runtime = %+v", pkgs[0])
			}
		})
	}
}

func TestJavaClassPrefixBound(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for i := 0; i < 2100; i++ {
		prefix := "org/first/lib"
		if i >= 1001 {
			prefix = "com/second/lib"
		}
		if _, err := z.Create(fmt.Sprintf("%s/C%d.class", prefix, i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	pkgs, _ := catalog([]File{{Path: "lib-1.jar", Data: b.Bytes()}}, nil)
	if len(pkgs) != 1 || pkgs[0].Namespace != "org.first.lib" {
		t.Fatalf("packages = %+v", pkgs)
	}
}

func TestJavaRuntimeManifestDeduplication(t *testing.T) {
	var files []File
	for _, name := range []string{"rt.jar", "jsse.jar", "charsets.jar"} {
		files = append(files, File{Path: "jre/lib/" + name, Data: gapZIP(t, map[string][]byte{
			"META-INF/MANIFEST.MF": []byte("Implementation-Title: Java Runtime Environment\nImplementation-Version: 17.0.20\nImplementation-Vendor: Oracle Corporation\n"),
		})})
	}
	pkgs, _ := catalog(files, nil)
	if len(pkgs) != 1 {
		t.Fatalf("packages = %+v", pkgs)
	}
	p := pkgs[0]
	if p.Type != "generic" || p.Name != "openjdk" || p.Version != "17.0.20" || p.CPE != "cpe:2.3:a:oracle:openjdk:17.0.20:*:*:*:*:*:*:*" || packageJSONField(t, p, "evidence") != "installed" {
		t.Fatalf("runtime = %+v", p)
	}
}

func TestJavaPOMEvidence(t *testing.T) {
	for _, group := range []string{"org.example", ""} {
		data := gapZIP(t, map[string][]byte{"META-INF/maven/org.example/lib/pom.properties": []byte("groupId=" + group + "\nartifactId=lib\nversion=1\n")})
		pkgs, _ := catalog([]File{{Path: "lib.jar", Data: data}}, nil)
		if len(pkgs) != 1 || packageJSONField(t, pkgs[0], "evidence") != "installed" {
			t.Fatalf("packages = %+v", pkgs)
		}
		if group == "" && pkgs[0].PURL != "pkg:generic/lib@1" {
			t.Fatalf("unknown group: %+v", pkgs[0])
		}
	}
}

func TestJavaEvidenceMerge(t *testing.T) {
	manifest := File{Path: "lib.jar", Data: gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Implementation-Vendor-Id: org.example\nImplementation-Version: 1\n")})}
	pom := File{Path: "lib-copy.jar", Data: gapZIP(t, map[string][]byte{"META-INF/maven/org.example/lib/pom.properties": []byte("groupId=org.example\nartifactId=lib\nversion=1\n")})}
	for _, files := range [][]File{{manifest, pom}, {pom, manifest}} {
		pkgs, _ := catalog(files, nil)
		if len(pkgs) != 1 || pkgs[0].Evidence != "installed" {
			t.Fatalf("packages = %+v", pkgs)
		}
	}
}

func TestJavaRuntimeVendorMerge(t *testing.T) {
	unknown := File{Path: "jre/lib/rt.jar", Data: gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Implementation-Title: Java Runtime Environment\nImplementation-Version: 17.0.20\n")})}
	oracle := File{Path: "jre/lib/jsse.jar", Data: gapZIP(t, map[string][]byte{"META-INF/MANIFEST.MF": []byte("Implementation-Title: Java Runtime Environment\nImplementation-Version: 17.0.20\nImplementation-Vendor: Oracle Corporation\n")})}
	for _, files := range [][]File{{unknown, oracle}, {oracle, unknown}} {
		pkgs, _ := catalog(files, nil)
		if len(pkgs) != 1 || pkgs[0].PURL != "pkg:generic/openjdk@17.0.20" || pkgs[0].CPE == "" {
			t.Fatalf("packages = %+v", pkgs)
		}
	}
}
