package purl

import "testing"

func TestReviewEncodedSlashNames(t *testing.T) {
	for _, typ := range []string{"generic", "maven", "deb", "apk", "cargo", "pypi", "npm"} {
		t.Run(typ, func(t *testing.T) {
			input := "pkg:" + typ + "/a%2Fb@1"
			p, err := Parse(input)
			if err != nil {
				t.Fatal(err)
			}
			if p.Namespace != "" || p.Name != "a/b" || p.String() != input {
				t.Fatalf("changed encoded name: %+v (%s)", p, p.String())
			}
		})
	}
}

func TestReviewColonVersionAndQualifiers(t *testing.T) {
	want := "pkg:deb/debian/git@1:2.47.3-0%2Bdeb13u1?upstream=git-src%402:3"
	for _, input := range []string{want, "pkg:deb/debian/git@1%3A2.47.3-0%2Bdeb13u1?upstream=git-src%402%3A3"} {
		p, err := Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		if p.Version != "1:2.47.3-0+deb13u1" || p.Qualifiers["upstream"] != "git-src@2:3" || p.String() != want {
			t.Fatalf("got %+v (%s), want %s", p, p.String(), want)
		}
	}
}
