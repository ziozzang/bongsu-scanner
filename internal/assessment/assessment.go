// Package assessment provides optional, evidence-grounded LLM applicability
// hints. Its results never replace deterministic vulnerability findings.
package assessment

import (
	"context"
	"time"
)

const (
	MaxDescriptionBytes = 64 << 10
	MaxSummaryBytes     = 8192
	MaxReferences       = 32
	MaxReferenceBytes   = 2048

	LikelyAffected    = "likely_affected"
	LikelyNotAffected = "likely_not_affected"
	NeedsReview       = "needs_review"
	// NotAssessed is reserved for local callers skipping analysis, never model output.
	NotAssessed = "not_assessed"
)

type Environment struct {
	OS        string            `json:"os"`
	OSVersion string            `json:"os_version,omitempty"`
	Arch      string            `json:"arch,omitempty"`
	Facts     map[string]string `json:"facts,omitempty"`
}
type Input struct {
	AdvisoryID           string      `json:"advisory_id"`
	Summary              string      `json:"summary"`
	Description          string      `json:"description"`
	DescriptionTruncated bool        `json:"description_truncated"`
	Package              string      `json:"package"`
	Version              string      `json:"version"`
	Ecosystem            string      `json:"ecosystem"`
	Environment          Environment `json:"environment"`
	References           []string    `json:"references,omitempty"`
}
type Result struct {
	Status        string   `json:"status"`
	Reason        string   `json:"reason"`
	Evidence      []string `json:"evidence"`
	Preconditions []string `json:"preconditions"`
	Checks        []string `json:"checks"`
	Model         string   `json:"model"`
	InputSHA256   string   `json:"input_sha256"`
	Cached        bool     `json:"cached"`
}
type Analyzer interface {
	Analyze(context.Context, Input) (Result, error)
}
type Config struct {
	BaseURL, APIKey, Model, CacheDir string
	Timeout                          time.Duration
}
