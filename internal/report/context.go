package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ziozzang/bongsu-scanner/internal/scan"
)

func object(v any) map[string]any             { m, _ := v.(map[string]any); return m }
func array(v any) []any                       { a, _ := v.([]any); return a }
func str(m map[string]any, key string) string { s, _ := m[key].(string); return s }

// ContextFromSBOM reads bscan's CycloneDX properties or SPDX annotations.
// Absent metadata stays nil; malformed typed metadata is an error.
func ContextFromSBOM(path string) (target string, scanMeta *scan.ScanMetadata, osMeta *scan.OSRelease, image *scan.ImageMetadata, host *scan.HostMetadata, err error) {
	b, e := os.ReadFile(path)
	if e != nil {
		err = e
		return
	}
	var doc map[string]any
	if err = json.Unmarshal(b, &doc); err != nil {
		return
	}
	switch {
	case str(doc, "bomFormat") == "CycloneDX":
		root := object(object(doc["metadata"])["component"])
		target = str(root, "name")
		props := map[string]string{}
		readProps := func(v any) {
			for _, x := range array(v) {
				p := object(x)
				props[str(p, "name")] = str(p, "value")
			}
		}
		readProps(root["properties"])
		var walk func([]any)
		walk = func(xs []any) {
			for _, x := range xs {
				c := object(x)
				if str(c, "type") == "operating-system" && osMeta == nil {
					osMeta = &scan.OSRelease{ID: str(c, "name"), VersionID: str(c, "version")}
					readProps(c["properties"])
				}
				walk(array(c["components"]))
			}
		}
		walk(array(doc["components"]))
		walk([]any{root})
		// Translate property names to the JSON tags of scan's existing metadata.
		groups := map[string]map[string]any{}
		for k, v := range props {
			parts := strings.SplitN(k, ":", 3)
			if len(parts) != 3 || parts[0] != "bscan" {
				continue
			}
			group, key := parts[1], strings.ReplaceAll(parts[2], "-", "_")
			if groups[group] == nil {
				groups[group] = map[string]any{}
			}
			var value any = v
			switch group + ":" + key {
			case "scan:partial", "scan:in_container":
				value, e = strconv.ParseBool(v)
			case "scan:euid", "scan:permission_denied", "scan:skipped_errors", "scan:metadata_skipped", "scan:excluded_count", "scan:files_visited", "host:cpu_count":
				var n int64
				n, e = strconv.ParseInt(v, 10, 64)
				value = n
			case "host:memory_bytes":
				var n uint64
				n, e = strconv.ParseUint(v, 10, 64)
				value = n
			case "scan:excluded", "scan:skipped_paths":
				value = split(v, ";")
			case "host:ip_addresses", "image:tags", "image:repo_digests":
				value = split(v, ",")
			}
			if e != nil {
				err = fmt.Errorf("SBOM property %s: %w", k, e)
				return
			}
			groups[group][key] = value
		}
		decode := func(group string, out any) error {
			v, ok := groups[group]
			if !ok {
				return nil
			}
			b, e := json.Marshal(v)
			if e != nil {
				return e
			}
			return json.Unmarshal(b, out)
		}
		if err = decode("scan", &scanMeta); err != nil {
			return
		}
		if err = decode("host", &host); err != nil {
			return
		}
		if err = decode("image", &image); err != nil {
			return
		}
		if groups["os"] != nil {
			if osMeta == nil {
				osMeta = &scan.OSRelease{}
			}
			if err = decode("os", osMeta); err != nil {
				return
			}
		}
		if image != nil {
			type indexedLayer struct {
				index int
				layer scan.LayerInfo
			}
			var layers []indexedLayer
			for k, v := range props {
				if !strings.HasPrefix(k, "bscan:image:layer:") {
					continue
				}
				n, e := strconv.Atoi(strings.TrimPrefix(k, "bscan:image:layer:"))
				if e != nil || n < 0 {
					err = fmt.Errorf("invalid image layer index %q", k)
					return
				}
				fields := strings.Fields(v)
				if len(fields) == 0 {
					continue
				}
				l := scan.LayerInfo{Digest: fields[0]}
				for _, field := range fields[1:] {
					key, value, _ := strings.Cut(field, "=")
					switch key {
					case "diff_id":
						l.DiffID = value
					case "verified":
						l.Verified, e = strconv.ParseBool(value)
						if e != nil {
							err = e
							return
						}
					}
				}
				layers = append(layers, indexedLayer{n, l})
			}
			sort.Slice(layers, func(i, j int) bool { return layers[i].index < layers[j].index })
			for _, l := range layers {
				image.Layers = append(image.Layers, l.layer)
			}
		}
	case strings.HasPrefix(str(doc, "spdxVersion"), "SPDX-"):
		target = str(doc, "name")
		for _, x := range array(doc["packages"]) {
			p := object(x)
			switch str(p, "SPDXID") {
			case "SPDXRef-Root":
				if name := str(p, "name"); name != "" {
					target = name
				}
				comments := []string{str(p, "comment")}
				for _, a := range array(p["annotations"]) {
					comments = append(comments, str(object(a), "comment"))
				}
				for _, comment := range comments {
					for _, kind := range []string{"scan", "host", "image"} {
						prefix := "bscan " + kind + " metadata: "
						if !strings.HasPrefix(comment, prefix) {
							continue
						}
						data := []byte(strings.TrimPrefix(comment, prefix))
						switch kind {
						case "scan":
							err = json.Unmarshal(data, &scanMeta)
						case "host":
							err = json.Unmarshal(data, &host)
						case "image":
							err = json.Unmarshal(data, &image)
						}
						if err != nil {
							err = fmt.Errorf("SPDX %s metadata: %w", kind, err)
							return
						}
					}
				}
			case "SPDXRef-OperatingSystem":
				osMeta = &scan.OSRelease{ID: str(p, "name"), VersionID: str(p, "versionInfo"), PrettyName: str(p, "summary")}
				for _, note := range strings.Split(strings.TrimPrefix(str(p, "comment"), "bscan os-release: "), "; ") {
					key, value, _ := strings.Cut(note, "=")
					switch key {
					case "codename":
						osMeta.Codename = value
					case "id_like":
						osMeta.IDLike = value
					}
				}
			}
		}
	default:
		err = fmt.Errorf("unsupported SBOM format")
		return
	}
	if scanMeta != nil && scanMeta.ExcludedCount < len(scanMeta.Excluded) {
		scanMeta.ExcludedCount = len(scanMeta.Excluded)
	}
	return
}
func split(s, sep string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, sep)
}
