package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOfflineRegistryDispatch(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected request", 404)
	}))
	defer server.Close()
	for _, scheme := range []string{"registry://", "oci://"} {
		for _, direct := range []bool{false, true} {
			target := scheme + strings.TrimPrefix(server.URL, "http://") + "/fixture:latest"
			opts := Options{Offline: true, InsecureRegistry: true, Progress: func(p Progress) { t.Errorf("unexpected progress before rejection: %+v", p) }}
			call := Target
			if direct {
				call = registryImage
			}
			_, err := call(context.Background(), target, opts)
			if err == nil || !strings.Contains(err.Error(), "offline") {
				t.Fatalf("target=%s direct=%t: %v", target, direct, err)
			}
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("offline sent %d requests", requests.Load())
	}
}

func TestOfflineAllowsLocalDocker(t *testing.T) {
	layer := tarData(t, map[string][]byte{"etc/os-release": []byte("ID=alpine\nVERSION_ID=3.20\n")})
	log := fakeDocker(t, dockerArchive(t, layer), nil)
	r, err := Target(context.Background(), "docker://fixture:latest", Options{Offline: true})
	if err != nil || r.OSName != "alpine" {
		t.Fatalf("offline docker result=%+v error=%v (log=%s)", r, err, log)
	}
}
