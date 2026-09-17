package match

import (
	"bytes"
	"errors"
	"testing"
)

type outputStreamFailure struct{ err error }

func (w outputStreamFailure) Write([]byte) (int, error) { return 0, w.err }

type outputStreamDirect struct{ *bytes.Buffer }

func TestOutputCycloneDXReservationAndWriteErrors(t *testing.T) {
	d, err := LoadFile(streamFixtureFile(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"fixture"}],"vulnerabilities":[{"id":"old"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := Report{Findings: []Finding{{ID: "CVE-fixture", Subject: d.Subjects[0]}}}
	var reserved, direct bytes.Buffer
	reserved.WriteString("prefix\n")
	direct.WriteString("prefix\n")
	if err := Write(&reserved, "cyclonedx", r, d); err != nil {
		t.Fatal(err)
	}
	if err := Write(outputStreamDirect{&direct}, "cyclonedx", r, d); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reserved.Bytes(), direct.Bytes()) {
		t.Fatalf("reservation byte diff:\n-%s\n+%s", direct.Bytes(), reserved.Bytes())
	}
	sentinel := errors.New("output failed")
	if err := Write(outputStreamFailure{sentinel}, "cyclonedx", r, d); !errors.Is(err, sentinel) {
		t.Fatalf("lost writer error: %v", err)
	}
}
