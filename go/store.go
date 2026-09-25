// Store domain: the pieces of the on-disk layout this plugin still owns.
//
// The template store this file used to implement is gone: the plugin no longer
// reuses X-Codex-Turn-State at all (FINDINGS.md) -- the reusable credential is
// the account-agnostic __cflb/__oailb routing pair, whose pool lives in
// route-cookies.json and is handled by route_cookies.go. What remains here is
// the atomic write primitive the other top-level files still use, the bucket
// key the observation tally is still keyed on, and a one-shot reader that
// folds cookie fields out of the legacy per-bucket records into the pool so an
// upgrade does not start cold.

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// atomicWrite writes via a temporary file in the same directory and renames, so
// a reader never sees a half-written document. os.CreateTemp already creates
// with 0600 and rename preserves the mode, which is the permission the store
// needs.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, errTemp := os.CreateTemp(dir, ".tmp-*")
	if errTemp != nil {
		return errTemp
	}
	name := tmp.Name()
	// Harmless after a successful rename; the point is to not leave litter
	// behind on any of the failure paths below.
	defer func() { _ = os.Remove(name) }()

	if _, errWrite := tmp.Write(data); errWrite != nil {
		_ = tmp.Close()
		return errWrite
	}
	if errSync := tmp.Sync(); errSync != nil {
		_ = tmp.Close()
		return errSync
	}
	if errClose := tmp.Close(); errClose != nil {
		return errClose
	}
	return os.Rename(name, path)
}

// bucketKey joins the two halves with a NUL, which cannot appear in either, so
// no pair of distinct (account, model) can collide onto one key. Kept for the
// observation tally, which is still keyed by bucket.
func bucketKey(authID, model string) string {
	return authID + "\x00" + model
}

// legacyRouteCookieEntries reads the cookie fields out of bucket records
// written by the pre-pool format (<store_dir>/<auth_id>/<model>.json carrying
// route_cookies). The records themselves are never written any more; this only
// folds their still-live pairs into the pool on load, and is deliberately
// forgiving -- a malformed or vanished file is skipped, never fatal, because
// the worst case is a pool one entry poorer.
func legacyRouteCookieEntries(dir string) []routeCookieEntry {
	authDirs, errRead := os.ReadDir(dir)
	if errRead != nil {
		return nil
	}
	var out []routeCookieEntry
	for _, authDir := range authDirs {
		if !authDir.IsDir() {
			continue
		}
		files, errAuth := os.ReadDir(filepath.Join(dir, authDir.Name()))
		if errAuth != nil {
			continue
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			data, errFile := os.ReadFile(filepath.Join(dir, authDir.Name(), file.Name()))
			if errFile != nil {
				continue
			}
			var legacy struct {
				RouteCookies       map[string]string `json:"route_cookies"`
				RouteCookiesAt     string            `json:"route_cookies_at"`
				RouteCookiesExpire string            `json:"route_cookies_expire"`
			}
			if errUnmarshal := json.Unmarshal(data, &legacy); errUnmarshal != nil {
				continue
			}
			if len(legacy.RouteCookies) == 0 || legacy.RouteCookiesAt == "" {
				continue
			}
			out = append(out, routeCookieEntry{
				Pairs:    legacy.RouteCookies,
				Gateway:  gatewayLabel(legacy.RouteCookies),
				SeenAt:   legacy.RouteCookiesAt,
				ExpireAt: legacy.RouteCookiesExpire,
			})
		}
	}
	return out
}

// bucketRelPath is the path sanitiser the management surface uses on
// caller-supplied auth_id/model. The store no longer lays files out per
// bucket, but the rule survives for its second job: anything interpolated into
// a filename or an outbound call must not be able to walk out of its
// directory. It returns the safe "<auth>/<model>.json" form, or an error that
// names which half was unsafe.
func bucketRelPath(authID, model string) (string, error) {
	safe := func(s string) bool {
		if s == "" || len(s) > 256 {
			return false
		}
		return strings.IndexAny(s, `/\`+"\x00") < 0 && !strings.Contains(s, "..")
	}
	if !safe(authID) {
		return "", fmt.Errorf("unsafe auth_id %q", authID)
	}
	if !safe(model) {
		return "", fmt.Errorf("unsafe model %q", model)
	}
	return authID + "/" + model + ".json", nil
}
