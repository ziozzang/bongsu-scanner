package main

import (
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ziozzang/bongsu-scanner/internal/config"
	"github.com/ziozzang/bongsu-scanner/internal/vulndb"
)

func TestResolveDBSelection(t *testing.T) {
	installed := vulndb.Meta{SchemaVersion: vulndb.SchemaVersion, Selection: &vulndb.Selection{Sources: []string{"osv", "nvd"}, Ecosystems: []string{"A"}, AlpineReleases: []string{"v3.19"}, NVDYears: "2024,2025", NVDEnabled: true}}
	defaults := vulndb.Meta{}.EffectiveSelection()
	for _, tc := range []struct {
		name       string
		old        vulndb.Meta
		cfg        config.DBConfig
		flags      []string
		adds       dbSelectionAdditions
		want       vulndb.Selection
		provenance string
	}{
		{name: "defaults", want: defaults, provenance: "defaults"},
		{name: "sticky", old: installed, want: *installed.Selection, provenance: "installed catalog"},
		{name: "flags replace field", old: installed, flags: []string{"--ecosystem=B"}, want: vulndb.Selection{Sources: []string{"osv", "nvd"}, Ecosystems: []string{"B"}, AlpineReleases: []string{"v3.19"}, NVDYears: "2024,2025", NVDEnabled: true}, provenance: "flags + installed catalog"},
		{name: "config replaces field", old: installed, cfg: config.DBConfig{Ecosystems: []string{"C"}}, want: vulndb.Selection{Sources: []string{"osv", "nvd"}, Ecosystems: []string{"C"}, AlpineReleases: []string{"v3.19"}, NVDYears: "2024,2025", NVDEnabled: true}, provenance: "config + installed catalog"},
		{name: "flags beat config and disable NVD", old: installed, cfg: config.DBConfig{Sources: []string{"nvd"}, Ecosystems: []string{"C"}, NVDYears: "2023"}, flags: []string{"--source=osv", "--ecosystem=B", "--nvd-years=2022"}, want: vulndb.Selection{Sources: []string{"osv"}, Ecosystems: []string{"B"}, AlpineReleases: []string{"v3.19"}, NVDYears: "2022"}, provenance: "flags + installed catalog"},
		{name: "explicit empty uses defaults", old: installed, flags: []string{"--source=", "--ecosystem=", "--alpine-release=", "--nvd-years="}, want: defaults, provenance: "flags"},
		{name: "add ordered aliases", old: installed, adds: dbSelectionAdditions{sources: dbAdditionList{"alpine", "alpine-secdb", "osv"}, ecosystems: dbAdditionList{"B", "A", "Ubuntu:24.04", "Ubuntu:24.04:LTS"}, releases: dbAdditionList{"v3.20", "v3.19"}}, want: vulndb.Selection{Sources: []string{"osv", "nvd", "alpine-secdb"}, Ecosystems: []string{"A", "B", "Ubuntu"}, AlpineReleases: []string{"v3.19", "v3.20"}, NVDYears: "2024,2025", NVDEnabled: true}, provenance: "installed catalog + --add-source + --add-ecosystem + --add-alpine-release"},
		{name: "default tokens", flags: []string{"--source=default,osv", "--ecosystem=default,Ubuntu:24.04:LTS,defaults", "--alpine-release=defaults,v3.23"}, want: vulndb.Selection{Sources: defaults.Sources, Ecosystems: append(append([]string{}, defaults.Ecosystems...), "Ubuntu"), AlpineReleases: append(append([]string{}, defaults.AlpineReleases...), "v3.23")}, provenance: "flags + defaults"},
		{name: "add defaults", old: installed, adds: dbSelectionAdditions{ecosystems: dbAdditionList{"default"}}, want: vulndb.Selection{Sources: installed.Selection.Sources, Ecosystems: append([]string{"A"}, defaults.Ecosystems...), AlpineReleases: installed.Selection.AlpineReleases, NVDYears: "2024,2025", NVDEnabled: true}, provenance: "installed catalog + --add-ecosystem"},
		{name: "legacy feed declarations", old: vulndb.Meta{SchemaVersion: 1, Ecosystems: []string{"Wrong:12"}, Sources: []vulndb.SourceMeta{{Name: "osv", Ecosystems: []string{"A"}}, {Name: "osv", Ecosystems: []string{"A", "B"}}}}, want: vulndb.Selection{Sources: defaults.Sources, Ecosystems: []string{"A", "B"}, AlpineReleases: defaults.AlpineReleases}, provenance: "installed catalog"},
		{name: "legacy no declarations", old: vulndb.Meta{SchemaVersion: 1, Ecosystems: []string{"Wrong:12"}}, want: defaults, provenance: "installed catalog"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("selection", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			for _, name := range []string{"source", "ecosystem", "alpine-release", "nvd-years"} {
				fs.String(name, "", "")
			}
			if err := fs.Parse(tc.flags); err != nil {
				t.Fatal(err)
			}
			if err := applyDBDefaults(fs, tc.cfg); err != nil {
				t.Fatal(err)
			}
			got, provenance, err := resolveDBSelection(fs, tc.cfg, tc.old, tc.adds)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) || provenance != tc.provenance {
				t.Fatalf("got %+v (%s), want %+v (%s)", got, provenance, tc.want, tc.provenance)
			}
		})
	}
}

func TestDBAdditionValidation(t *testing.T) {
	for _, value := range []string{"", " ", ",", "A,", ",B", "A,,B", "A/B", `A\B`, "A?B", "A#B"} {
		var list dbAdditionList
		if err := list.Set(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	var list dbAdditionList
	for _, value := range []string{"A,B", " C ", "default,defaults"} {
		if err := list.Set(value); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(list, ",") != "A,B,C,default,defaults" {
		t.Fatal(list)
	}
}
