package vulndb

import (
	"crypto/ed25519"
	"fmt"

	"github.com/ziozzang/bongsu-scanner/internal/httpx"
)

// Options selects upstream feeds and allows deployments to use mirrors.
// Empty source, ecosystem, release and URL fields use the defaults in source.go.
type Options struct {
	// Isolation selects SQLite reader isolation: auto (default) tries reflink
	// and otherwise holds the database shared lock; copy also permits a full
	// copy; none opens the source without retaining a lock.
	// auto detects concurrent modification; copy prevents it. Detection checks
	// inode, size, mtime and ctime after verification, each lookup and at Close;
	// it cannot prevent writes between checks or protect against a privileged
	// attacker able to forge ctime.
	// On Linux, auto and none reuse a private 0600 verification receipt when
	// the opened file's dev/inode/size/mtime/ctime, manifest digest, binary schema
	// versions and pinned-key fingerprint match. Manifest hashes and signatures
	// are always checked. Unprivileged SQLite writers cannot restore ctime;
	// the current UID's receipt and the kernel must be trusted. Root can replace
	// the binary and is outside this model. copy always hashes the complete file.
	// A freshly changed inode waits at most one second before verification to
	// avoid trusting multiple writes sharing a filesystem timestamp tick.
	Isolation string
	// SkipIsolation opens the verified SQLite source directly. The caller must
	// prevent replacement or mutation for the entire reader lifetime.
	// Deprecated: use Isolation="none". When true it overrides Isolation.
	SkipIsolation  bool
	Sources        []string
	Ecosystems     []string
	AlpineReleases []string
	OSVBaseURL     string
	AlpineBaseURL  string
	DebianURL      string
	GHSAURL        string
	MaxFeedBytes   int64
	Client         *httpx.Client
	Offline        bool
	Force          bool
	NoKeepRaw      bool
	PrivateKey     ed25519.PrivateKey
	PublicKey      ed25519.PublicKey
	Signer         string
	Progress       func(string)
}

func (o Options) isolationMode() (string, error) {
	if o.SkipIsolation {
		return "none", nil
	}
	switch o.Isolation {
	case "", "auto":
		return "auto", nil
	case "copy", "none":
		return o.Isolation, nil
	default:
		return "", fmt.Errorf("invalid database isolation %q (want auto, copy, or none)", o.Isolation)
	}
}
