package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testRecipe() *recipe {
	return &recipe{Presets: []presetSpec{{
		ID: "p", Name: "P", Category: "Test", Description: "test",
		Parts: []part{{Source: "local", Files: []string{"a.txt"}}},
	}}}
}

func testSources(root string) map[string]*loadedSource {
	return map[string]*loadedSource{
		"local": {name: "local", root: root, spec: source{Format: "plain"}},
	}
}

func TestComposeFiltersRulesByRoutingScope(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "host.registration.test\nbroad.test\nhost.broad.test\nother.test\n")
	r := testRecipe()
	p := &r.Presets[0]
	p.Exclude = []string{"broad.test"}
	p.ExcludeSubtrees = []string{"registration.test"}
	p.Parts[0].Only = []string{"host.registration.test", "broad.test", "host.broad.test"}
	snap := snapshotFile{Files: map[string]snapshotEntry{}}
	managed, _, err := compose(r, testSources(dir), &snap, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := managed["p"].Domains; !slices.Equal(got, []string{"host.broad.test"}) {
		t.Fatalf("routing suffixes = %v", got)
	}
}

func TestShrinkKeepsOldDomains(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "one.test\ntwo.test\n")
	snap := snapshotFile{Files: map[string]snapshotEntry{
		"local\x00a.txt": {Source: "local", File: "a.txt", SourceCount: 4, Domains: []string{"one.test", "two.test", "old.test"}},
	}}
	managed, _, err := compose(testRecipe(), testSources(dir), &snap, false)
	if err != nil {
		t.Fatal(err)
	}
	got := managed["p"].Domains
	if !slices.Contains(got, "old.test") || !slices.Contains(got, "one.test") {
		t.Fatalf("shrink lost preserved domains: %v", got)
	}
	if snap.Files["local\x00a.txt"].SourceCount != 2 {
		t.Fatalf("source count = %d", snap.Files["local\x00a.txt"].SourceCount)
	}
}

func TestMissingSourceKeepsOldDomains(t *testing.T) {
	dir := t.TempDir()
	snap := snapshotFile{Files: map[string]snapshotEntry{
		"local\x00a.txt": {Source: "local", File: "a.txt", SourceCount: 3, Domains: []string{"one.test", "two.test", "old.test"}},
	}}
	managed, _, err := compose(testRecipe(), testSources(dir), &snap, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(managed["p"].Domains) != 3 {
		t.Fatalf("missing source lost domains: %v", managed["p"].Domains)
	}
}

func TestGrowthReplacesSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.txt"), "one.test\ntwo.test\nthree.test\n")
	snap := snapshotFile{Files: map[string]snapshotEntry{
		"local\x00a.txt": {Source: "local", File: "a.txt", SourceCount: 2, Domains: []string{"one.test", "two.test"}},
	}}
	managed, _, err := compose(testRecipe(), testSources(dir), &snap, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(managed["p"].Domains) != 3 {
		t.Fatalf("growth result = %v", managed["p"].Domains)
	}
}

func TestV2flyIncludesAndAttributes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "data", "a"), "include:b\nfoo.com\nfull:exact.com\nbaz.com @ads\n")
	writeFile(t, filepath.Join(dir, "data", "b"), "bar.com\n")
	src := &loadedSource{name: "v2fly", root: dir, spec: source{Format: "v2fly", Dir: "data"}}
	got, err := readDomains(src, "a")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"foo.com", "bar.com"} {
		if !slices.Contains(got, want) {
			t.Fatalf("missing %s in %v", want, got)
		}
	}
	for _, unwanted := range []string{"exact.com", "baz.com"} {
		if slices.Contains(got, unwanted) {
			t.Fatalf("unexpected %s in %v", unwanted, got)
		}
	}
}

const githubRecipe = `schema: 1
sources:
  src:
    kind: github
    revision: deadbeef
    archive: https://codeload.github.com/example/repo/tar.gz/{revision}
    archive_sha256: archive
    license: %s
    license_path: LICENSE
    license_sha256: license
presets:
  - id: test
    name: Test
    category: Test
    parts:
      - source: src
        files: [file]
`

const localRecipe = `schema: 1
sources:
  local:
    kind: local
    origin: %s
    license: GPL-3.0-only
    license_path: LICENSE
presets:
  - id: test
    name: Test
    category: Test
    parts:
      - source: local
        files: [file]
`

func TestRecipeRejectsUnsafeSources(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"valid github", fmt.Sprintf(githubRecipe, "MIT"), false},
		{"unknown license", fmt.Sprintf(githubRecipe, "NOASSERTION"), true},
		{"denied host", strings.ReplaceAll(fmt.Sprintf(githubRecipe, "MIT"), "codeload.github.com", "kvaspro.su"), true},
		{"mutable archive", strings.ReplaceAll(fmt.Sprintf(githubRecipe, "MIT"), "/tar.gz/{revision}", "/tar.gz/main"), true},
		{"valid local", fmt.Sprintf(localRecipe, "project"), false},
		{"unowned local", fmt.Sprintf(localRecipe, ""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "recipe.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := loadRecipe(path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("loadRecipe() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizeRejectsSingleLabel(t *testing.T) {
	got := normalizeAll([]string{"domain", "example.com"})
	if !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("normalizeAll() = %v", got)
	}
}
