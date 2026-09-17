package vulndb

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

// Verbatim fixtures from https://github.com/rubysec/ruby-advisory-db (master).
var rubysecReviewFixtures = map[string]string{
	"repo/gems/actionpack/CVE-2013-1855.yml": `---
gem: actionpack
framework: rails
cve: 2013-1855
osvdb: 91452
ghsa: q759-hwvc-m3jg
url: https://nvd.nist.gov/vuln/detail/CVE-2013-1855
title: "CVE-2013-1855 rubygem-actionpack: css_sanitization: XSS vulnerability in sanitize_css"
date: 2013-03-19
description: |
  The sanitize_css method in lib/action_controller/vendor/html-scanner/html/sanitizer.rb
  in the Action Pack component in Ruby on Rails before 2.3.18, 3.0.x and 3.1.x before
  3.1.12, and 3.2.x before 3.2.13 does not properly handle \n (newline) characters,
  which makes it easier for remote attackers to conduct cross-site scripting (XSS)
  attacks via crafted Cascading Style Sheets (CSS) token sequences. A cross-site scripting
  (XSS) flaw was found in Action Pack. A remote attacker could use this flaw to conduct
  XSS attacks against users of an application using Action Pack.
cvss_v2: 4.3
patched_versions:
  - "~> 2.3.18"
  - "~> 3.1.12"
  - ">= 3.2.13"
`,
	"repo/gems/actionpack/CVE-2023-22792.yml": `---
gem: actionpack
framework: rails
cve: 2023-22792
ghsa: p84v-45xj-wwqj
url: https://github.com/rails/rails/releases/tag/v7.0.4.1
title: ReDoS based DoS vulnerability in Action Dispatch
date: 2023-01-18
description: |
  There is a possible regular expression based DoS vulnerability in Action
  Dispatch. This vulnerability has been assigned the CVE identifier
  CVE-2023-22792.

  Versions Affected: >= 3.0.0
  Not affected: < 3.0.0
  Fixed Versions: 6.1.7.1, 7.0.4.1

  # Impact

  Specially crafted cookies, in combination with a specially crafted
  X_FORWARDED_HOST header can cause the regular expression engine to enter a
  state of catastrophic backtracking. This can cause the process to use large
  amounts of CPU and memory, leading to a possible DoS vulnerability All users
  running an affected release should either upgrade or use one of the
  workarounds immediately.

  # Workarounds

  We recommend that all users upgrade to one of the FIXED versions. In the
  meantime, users can mitigate this vulnerability by using a load balancer or
  other device to filter out malicious X_FORWARDED_HOST headers before they
  reach the application.
unaffected_versions:
  - "< 3.0.0"
patched_versions:
  - "~> 5.2.8"
  - "~> 6.1.7, >= 6.1.7.1"
  - ">= 7.0.4.1"
`,
	"repo/gems/activesupport/CVE-2015-3226.yml": `---
gem: activesupport
framework: rails
cve: 2015-3226
ghsa: vxvp-4xwc-jpp6
url: https://groups.google.com/forum/#!topic/ruby-security-ann/7VlB_pck3hU
title: XSS Vulnerability in ActiveSupport::JSON.encode
date: 2015-06-16
description: |
  When a ` + "`" + `Hash` + "`" + ` containing user-controlled data is encode as JSON (either through
  ` + "`" + `Hash#to_json` + "`" + ` or ` + "`" + `ActiveSupport::JSON.encode` + "`" + `), Rails does not perform adequate
  escaping that matches the guarantee implied by the ` + "`" + `escape_html_entities_in_json` + "`" + `
  option (which is enabled by default). If this resulting JSON string is subsequently
  inserted directly into an HTML page, the page will be vulnerable to XSS attacks.

  For example, the following code snippet is vulnerable to this attack:

      <%= javascript_tag "var data = #{user_supplied_data.to_json};" %>

  Similarly, the following is also vulnerable:

      <script>
        var data = <%= ActiveSupport::JSON.encode(user_supplied_data).html_safe %>;
      </script>

  All applications that renders JSON-encoded strings that contains user-controlled
  data in their views should either upgrade to one of the FIXED versions or use
  the suggested workaround immediately.

  Workarounds
  -----------
  To work around this problem add an initializer with the following code:

    module ActiveSupport
      module JSON
        module Encoding
          private
          class EscapedString
            def to_s
              self
            end
          end
        end
      end
    end
unaffected_versions:
  - "< 4.1.0"
patched_versions:
  - ">= 4.2.2"
  - "~> 4.1.11"
`,
	"repo/gems/actionpack-page_caching/CVE-2020-8159.yml": `---
gem: actionpack-page_caching
cve: 2020-8159
ghsa: mg5p-95m9-rmfp
url: https://groups.google.com/forum/#!topic/rubyonrails-security/CFRVkEytdP8
title: Arbitrary file write/potential remote code execution in actionpack-page_caching
date: 2020-05-06
description: |
  There is a vulnerability in the actionpack-page_caching gem that allows an attacker
  to write arbitrary files to a web server, potentially resulting in remote code execution
  if the attacker can write unescaped ERB to a view.

  Versions Affected:  All versions of actionpack-page_caching (part of Rails prior to Rails 4.0)
  Not affected:       Applications not using actionpack-page_caching
  Fixed Versions:     actionpack-page_caching >= 1.2.1

  Impact
  ------

  The Action Pack Page Caching gem writes cache files to the file system in
  order for the front end webserver (nginx, Apache, etc) to serve the cached
  file without making a request to the application server.  Paths contain what
  is effectively user input can be used to manipulate the location of the cache
  file.

  For example "/users/123" could be changed to "/users/../../../foo" and this
  will escape the cache directory.  Attackers can use this technique to
  springboard to an RCE if they can write arbitrary ERb to a view folder.

  Impacted code looks like this:

  ` + "`" + `` + "`" + `` + "`" + `
  class BooksController < ApplicationController
    caches_page :show
  end
  ` + "`" + `` + "`" + `` + "`" + `

  Where the ` + "`" + `show` + "`" + ` action of the ` + "`" + `BooksController` + "`" + ` may be vulnerable.
cvss_v3: 9.8
patched_versions:
  - ">= 1.2.1"
`,
}

func TestRubysecReviewRealAdvisories(t *testing.T) {
	p := filepath.Join(t.TempDir(), "feed.zip")
	if err := os.WriteFile(p, fixtureZip(t, rubysecReviewFixtures), 0600); err != nil {
		t.Fatal(err)
	}
	count := 0
	err := parseRubysecZip(context.Background(), p, func(r *Record) error {
		count++
		a := r.Affected[0]
		if a.Database["rubysec_unmapped"] != nil {
			t.Errorf("%s unmapped: %v", r.ID, a.Database)
		}
		switch r.ID {
		case "CVE-2013-1855":
			rubysecAssertAffected(t, a, map[string]bool{"3.0.0": true, "3.2.13": false, "2.3.18": false, "2.4.0": true})
		case "CVE-2023-22792":
			rubysecAssertAffected(t, a, map[string]bool{"7.0.4": true, "7.0.4.1": false, "6.1.7.1": false, "6.1.7": true})
		case "CVE-2015-3226":
			rubysecAssertAffected(t, a, map[string]bool{"4.1.10": true, "4.1.11": false})
		case "CVE-2020-8159":
			if !reflect.DeepEqual(r.Severity, []Severity{{Type: "CVSS_V3", Score: "9.8"}}) {
				t.Errorf("severity: %+v", r.Severity)
			}
		}
		return nil
	})
	if err != nil || count != 4 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestRubysecReviewRequirements(t *testing.T) {
	for _, tc := range []struct {
		req   string
		cases map[string]bool
	}{
		{"~> 1.2", map[string]bool{"1.1": true, "1.2": false, "1.9": false, "2.0": true, "2.0.0-rc.1": true}},
		{"~> 1.2.3.4", map[string]bool{"1.2.3.3": true, "1.2.3.4": false, "1.2.3.9": false, "1.2.4": true}},
		{"~> 6.1.7, >= 6.1.7.1", map[string]bool{"6.1.7": true, "6.1.7.1": false, "6.2": true}},
		{"= 1.2", map[string]bool{"1.1": true, "1.2": false, "1.2.0.1": true, "1.3": true}},
		{"!= 1.2", map[string]bool{"1.1": false, "1.2": true, "1.2.0.1": false}},
		{"> 1.2", map[string]bool{"1.1": true, "1.2": true, "1.2.0.1": false}},
		{"<= 1.2", map[string]bool{"1.1": false, "1.2": false, "1.2.0.1": true}},
		{"< 1.2", map[string]bool{"1.1": false, "1.2": true}},
		{">= 1.2.0.rc1", map[string]bool{"1.2.0-beta.1": true, "1.2.0-rc.1": false, "1.2.0": false}},
		{">= 2, < 1", map[string]bool{"0.5": true, "1.5": true, "2.5": true}},
	} {
		t.Run(tc.req, func(t *testing.T) {
			rs, why := rubysecRanges([]string{tc.req}, nil)
			if len(why) != 0 {
				t.Fatal(why)
			}
			rubysecAssertAffected(t, Affected{Ranges: rs}, tc.cases)
		})
	}
	rs, why := rubysecRanges([]string{">= 7.0.4.1", "broken"}, []string{"< 1", "bad"})
	if !reflect.DeepEqual(why, []string{"broken", "bad"}) {
		t.Errorf("unmapped=%q", why)
	}
	rubysecAssertAffected(t, Affected{Ranges: rs}, map[string]bool{"0.5": false, "7.0.4": true, "7.0.4.1": false})
	rs, why = rubysecRanges(nil, nil)
	if len(why) != 0 {
		t.Fatal(why)
	}
	rubysecAssertAffected(t, Affected{Ranges: rs}, map[string]bool{"1.0": true, "99": true})
}

func TestRubysecReviewYAML(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{`title: "a\/b\e\xE9\u263A"`, "a/b\x1bé☺"},
		{"description: | # comment\n  one\n  two\n", "one\ntwo\n"},
		{"description: |2- # comment\n    one\n  two\n", "  one\ntwo"},
		{"description: >-\n  one\n  two\n", "one two"},
		{"description: |+\n  one\n\n", "one\n\n"},
	} {
		fields, err := readRubysecYAML(tc.yaml)
		if err != nil {
			t.Error(err)
			continue
		}
		key := "description"
		if strings.HasPrefix(tc.yaml, "title:") {
			key = "title"
		}
		if !reflect.DeepEqual(fields[key], []string{tc.want}) {
			t.Errorf("%q: got %q want %q", tc.yaml, fields[key], tc.want)
		}
	}
	for _, data := range []string{"description: |\n" + strings.Repeat("  line\n", 60000), "description: plain\n" + strings.Repeat("  line\n", 60000), `title: "bad\q"`} {
		p := filepath.Join(t.TempDir(), "feed.zip")
		if err := os.WriteFile(p, fixtureZip(t, map[string]string{"repo/gems/example/local.yml": data}), 0600); err != nil {
			t.Fatal(err)
		}
		err := parseRubysecZip(context.Background(), p, func(*Record) error { return nil })
		if err == nil || !strings.Contains(err.Error(), "local.yml") {
			t.Errorf("error should name file: %v", err)
		}
		if strings.HasPrefix(data, "description") && err != nil && !strings.Contains(err.Error(), "scalar exceeds") {
			t.Errorf("unclear size error: %v", err)
		}
	}
}

func TestRubysecReviewNumericSeverity(t *testing.T) {
	r, err := rubysecRecord("gem", "local", map[string][]string{"cvss_v2": {"4.3", "AV:N/AC:L/Au:N/C:P/I:N/A:N"}, "cvss_v3": {"9.8"}, "cvss_v4": {"10.0"}})
	if err != nil || len(r.Severity) != 4 {
		t.Fatalf("severity=%+v err=%v", r.Severity, err)
	}
}

func TestRubysecReviewHigherPrecision(t *testing.T) {
	for _, tc := range []struct {
		req   string
		cases map[string]bool
	}{
		{"~> 1.2.3.4.5", map[string]bool{"1.2.3.4": true, "1.2.3.5": true}},
		{"~> 1.2.3.0.0", map[string]bool{"1.2.3": false, "1.2.3.1": true}},
		{">= 1.2.3.0.0.1", map[string]bool{"1.2.3": true, "1.2.3.1-0": false, "1.2.4": false}},
		{"< 1.2.3.0.0.1", map[string]bool{"1.2.3": false, "1.2.3.1": true}},
	} {
		rs, why := rubysecRanges([]string{tc.req}, nil)
		if len(why) > 0 {
			t.Fatal(why)
		}
		rubysecAssertAffected(t, Affected{Ranges: rs}, tc.cases)
	}
}

func TestRubysecReviewArchiveCoverage(t *testing.T) {
	filename := os.Getenv("BONGSU_RUBYSEC_TEST_ARCHIVE")
	if filename == "" {
		t.Skip("set BONGSU_RUBYSEC_TEST_ARCHIVE to the downloaded archive")
	}
	count, ranges, unmapped, severities, targets := 0, 0, 0, 0, 0
	err := parseRubysecZip(context.Background(), filename, func(r *Record) error {
		count++
		if len(r.Affected[0].Ranges) > 0 {
			ranges++
		} else {
			t.Logf("empty vulnerable set: %s/%s", r.Affected[0].Package, r.ID)
		}
		if len(r.Severity) > 0 {
			severities++
		}
		if constraints, ok := r.Affected[0].Database["rubysec_unmapped"].([]string); ok {
			unmapped += len(constraints)
			t.Logf("unmapped %s: %v", r.ID, constraints)
		}
		switch r.ID + "/" + r.Affected[0].Package {
		case "CVE-2013-1855/actionpack":
			targets++
			rubysecAssertAffected(t, r.Affected[0], map[string]bool{"3.0.0": true, "3.2.13": false, "2.3.18": false})
		case "CVE-2023-22792/actionpack":
			targets++
			rubysecAssertAffected(t, r.Affected[0], map[string]bool{"7.0.4": true, "7.0.4.1": false, "6.1.7.1": false})
		case "CVE-2015-3226/activesupport":
			targets++
			rubysecAssertAffected(t, r.Affected[0], map[string]bool{"4.1.10": true, "4.1.11": false})
		}
		return nil
	})
	if err != nil || targets != 3 {
		t.Fatalf("targets=%d err=%v", targets, err)
	}
	t.Logf("advisories=%d with_ranges=%d unmapped_constraints=%d with_severity=%d", count, ranges, unmapped, severities)
}

func TestRubysecReviewWarningsAndExplicitSources(t *testing.T) {
	archive := fixtureZip(t, map[string]string{"repo/gems/example/local.yml": "patched_versions:\n- '>= 2'\n- 'unsupported; entry'\nunaffected_versions:\n- '< 1'\n- 'another unsupported'\n"})
	client := httpx.New(time.Second)
	client.HTTP.Transport = rubysecTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: int64(len(archive)), Body: io.NopCloser(strings.NewReader(string(archive)))}, nil
	})
	var progress []string
	meta, err := Update(context.Background(), filepath.Join(t.TempDir(), "db"), Options{Sources: []string{SourceRubysec}, Client: client, Progress: func(s string) { progress = append(progress, s) }})
	if err != nil || len(meta.Sources) != 1 || meta.Sources[0].Error != "" {
		t.Fatalf("meta=%+v err=%v", meta, err)
	}
	if !strings.Contains(strings.Join(progress, "\n"), "warning: 2 unmapped requirement entries") {
		t.Fatalf("warning missing: %v", progress)
	}
	r, err := rubysecRecord("example", "local", map[string][]string{"patched_versions": {">= 2", "unsupported; entry"}})
	if err != nil || !reflect.DeepEqual(r.Affected[0].Database["rubysec_unmapped"], []string{"unsupported; entry"}) {
		t.Fatalf("record=%+v err=%v", r, err)
	}

	archive = fixtureZip(t, map[string]string{"a.json": osvFixture("CVE-2026-1234", "RubyGems", "example")})
	requests := 0
	client.HTTP.Transport = rubysecTransport(func(req *http.Request) (*http.Response, error) {
		requests++
		if strings.Contains(req.URL.String(), "ruby-advisory-db") {
			t.Error("explicit source selection fetched rubysec")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, ContentLength: int64(len(archive)), Body: io.NopCloser(strings.NewReader(string(archive)))}, nil
	})
	meta, err = Update(context.Background(), filepath.Join(t.TempDir(), "db"), Options{Sources: []string{SourceOSV}, Ecosystems: []string{"RubyGems"}, Client: client})
	if err != nil || len(meta.Sources) != 1 || meta.Sources[0].Name != SourceOSV || requests != 1 {
		t.Fatalf("explicit sources: %+v requests=%d err=%v", meta, requests, err)
	}
}
