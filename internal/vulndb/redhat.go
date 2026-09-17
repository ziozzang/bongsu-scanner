package vulndb

import "strings"

func redHatRelease(suffix string) string {
	product, rest, ok := strings.Cut(suffix, ":")
	if !ok {
		return suffix
	}
	version, _, _ := strings.Cut(rest, ":")
	switch product {
	case "enterprise_linux":
		parts := strings.Split(version, ".")
		for _, part := range parts {
			if part == "" || strings.Trim(part, "0123456789") != "" {
				return suffix
			}
		}
		return parts[0]
	case "rhel_eus", "rhel_e4s", "rhel_aus", "rhel_tus", "rhel_els", "rhel_eus_long_life", "enterprise_linux_eus":
		// Lifecycle streams remain available to catalog lookups but never share
		// a plain host's major-version key. Their fixed builds (e.g. *.el9_4)
		// are not comparable with mainline builds and would cause false positives.
		return product + ":" + version
	default:
		return suffix
	}
}
