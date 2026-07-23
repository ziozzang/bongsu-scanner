package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ziozzang/bongsu-scanner/internal/selfupdate"
)

const updateRepo = "ziozzang/bongsu-scanner"

type updateCache struct {
	Checked time.Time `json:"checked_at"`
	Latest  string    `json:"latest"`
}

func cmdUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "check without installing")
	force := fs.Bool("force", false, "install even if current")
	repo := fs.String("repo", updateRepo, "GitHub owner/repository")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	client := &http.Client{}
	rel, err := selfupdate.Latest(ctx, client, *repo, os.Getenv("GITHUB_TOKEN"))
	if err != nil {
		return err
	}
	latest := rel.Version()
	fmt.Printf("current: %s\nlatest:  %s\n", version, latest)
	if *check || (selfupdate.Compare(latest, version) <= 0 && !*force) {
		return nil
	}
	name, err := selfupdate.AssetName(latest)
	if err != nil {
		return err
	}
	asset, ok := rel.Find(name)
	if !ok {
		return fmt.Errorf("release %s has no asset %s", rel.TagName, name)
	}
	sums, err := selfupdate.Checksums(ctx, client, rel)
	if err != nil {
		return err
	}
	if sums[name] == "" {
		return fmt.Errorf("SHA256SUMS has no entry for %s", name)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	tmp, err := selfupdate.DownloadVerified(ctx, client, asset, sums[name], filepath.Dir(exe))
	if err != nil {
		return err
	}
	dest, err := selfupdate.Replace(tmp)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Printf("updated %s to %s\n", dest, latest)
	return nil
}

// refreshUpdateCache is non-blocking and soft-fails for offline/air-gapped use.
func refreshUpdateCache(args []string) {
	if os.Getenv("BONGSU_NO_UPDATE_CHECK") != "" || len(args) == 0 || args[0] == "update" || args[0] == "version" {
		return
	}
	if info, err := os.Stderr.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return
	}
	path := updateCachePath()
	var c updateCache
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.Latest != "" && time.Since(c.Checked) < 24*time.Hour {
		if selfupdate.Compare(c.Latest, version) > 0 {
			fmt.Fprintf(os.Stderr, "bongsu %s is available; run 'bongsu update'\n", c.Latest)
		}
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rel, err := selfupdate.Latest(ctx, &http.Client{}, updateRepo, os.Getenv("GITHUB_TOKEN"))
		if err != nil {
			return
		}
		b, _ := json.Marshal(updateCache{Checked: time.Now(), Latest: rel.Version()})
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		tmp, err := os.CreateTemp(filepath.Dir(path), ".update-*")
		if err == nil {
			_, _ = tmp.Write(b)
			_ = tmp.Close()
			_ = os.Rename(tmp.Name(), path)
		}
	}()
}

func updateCachePath() string {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "bongsu", "update-check.json")
}
