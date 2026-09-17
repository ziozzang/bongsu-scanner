package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/report"
)

func cmdReport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	from := fs.String("from", "", "required match JSON file (one SBOM)")
	sbomPath := fs.String("sbom", "", "SBOM file supplying target and scan metadata")
	format := fs.String("format", "html", "html, markdown (md), json, csv, or sarif")
	output := fs.String("o", "", "output file (default stdout)")
	title := fs.String("title", "", "report target/title override")
	if err := parseCommandFlags(fs, args); err != nil {
		return err
	}
	if *from == "" {
		return fmt.Errorf("report: --from MATCH.json is required")
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("report: unexpected positional arguments")
	}
	switch *format {
	case "html", "markdown", "md", "json", "csv", "sarif":
	default:
		return fmt.Errorf("unsupported report format %q", *format)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(*from)
	if err != nil {
		return err
	}
	r, readErr := report.LoadMatchJSON(f)
	closeErr := f.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	in := report.Input{Report: r, Target: filepath.Base(*from), SBOMPath: *sbomPath, GeneratedAt: time.Now().UTC(), ToolVersion: version}
	if *sbomPath != "" {
		in.Target, in.Scan, in.OS, in.Image, in.Host, err = report.ContextFromSBOM(*sbomPath)
		if err != nil {
			return err
		}
	}
	if *title != "" {
		in.Target = *title
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if *output == "" {
		return report.Render(os.Stdout, *format, in)
	}
	// Publish only complete output, also allowing the input and output path to
	// coincide without truncating an unread input or leaving a partial report.
	return writeReportFile(*output, func(w io.Writer) error {
		if err := report.Render(w, *format, in); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func writeReportFile(path string, render func(io.Writer) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".bscan-report-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	err = render(f)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
