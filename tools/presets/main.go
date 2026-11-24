// Command presets generates the bundled domain preset catalog from pinned
// open sources and project-owned seed lists.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"gopkg.in/yaml.v3"
)

// preset matches the JSON consumed by KeenProxy without depending on its runtime.
type preset struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Domains     []string `json:"domains"`
	Prefixes    []string `json:"prefixes"`
	Description string   `json:"description"`
}

type recipe struct {
	Schema  int               `yaml:"schema"`
	Sources map[string]source `yaml:"sources"`
	Presets []presetSpec      `yaml:"presets"`
}

type source struct {
	Kind          string `yaml:"kind"`
	Origin        string `yaml:"origin"`
	Repo          string `yaml:"repo"`
	Revision      string `yaml:"revision"`
	Archive       string `yaml:"archive"`
	ArchiveSHA256 string `yaml:"archive_sha256"`
	License       string `yaml:"license"`
	LicensePath   string `yaml:"license_path"`
	LicenseSHA256 string `yaml:"license_sha256"`
	Format        string `yaml:"format"`
	Dir           string `yaml:"dir"`
}

type presetSpec struct {
	ID              string   `yaml:"id"`
	Name            string   `yaml:"name"`
	Category        string   `yaml:"category"`
	Description     string   `yaml:"description"`
	Parts           []part   `yaml:"parts"`
	Exclude         []string `yaml:"exclude"`
	ExcludeSubtrees []string `yaml:"exclude_subtrees"`
}

type part struct {
	Source string   `yaml:"source"`
	Files  []string `yaml:"files"`
	Only   []string `yaml:"only"`
}

type lockFile struct {
	Schema       int                   `json:"schema"`
	Sources      map[string]lockSource `json:"sources"`
	OutputSHA256 string                `json:"output_sha256"`
}

type lockSource struct {
	URL           string   `json:"url"`
	Revision      string   `json:"revision"`
	ArchiveSHA256 string   `json:"archive_sha256,omitempty"`
	License       string   `json:"license"`
	LicenseSHA256 string   `json:"license_sha256,omitempty"`
	LicenseFile   string   `json:"license_file"`
	Files         []string `json:"files"`
}

type snapshotFile struct {
	Schema int                      `json:"schema"`
	Files  map[string]snapshotEntry `json:"files"`
}

type snapshotEntry struct {
	Source      string   `json:"source"`
	File        string   `json:"file"`
	SourceCount int      `json:"source_count"`
	Domains     []string `json:"domains"`
}

type loadedSource struct {
	name        string
	spec        source
	root        string
	licenseText []byte
}

type options struct {
	recipe, base, out, lock, snapshot, snapshotOut, notices, sourcesDoc, licenses, cache, sourceRoot string
	check, dnsEnabled, offline                                                                       bool
}

func main() {
	var o options
	flag.StringVar(&o.recipe, "recipe", "tools/presets/recipe.yaml", "recipe file")
	flag.StringVar(&o.base, "base", "", "optional baseline for DNS comparison")
	flag.StringVar(&o.out, "out", "dist/presets.json", "generated catalog")
	flag.StringVar(&o.lock, "lock", "dist/sources.lock.json", "generated source lock")
	flag.StringVar(&o.snapshot, "snapshot", "tools/presets/sources.snapshot.json", "preserved per-file source snapshot")
	flag.StringVar(&o.snapshotOut, "snapshot-out", "dist/sources.snapshot.json", "generated per-file source snapshot")
	flag.StringVar(&o.notices, "notices", "dist/THIRD_PARTY_NOTICES.md", "generated third-party notices")
	flag.StringVar(&o.sourcesDoc, "sources-doc", "dist/PRESET_SOURCES.md", "generated preset source reference")
	flag.StringVar(&o.licenses, "licenses", "dist/LICENSES", "generated license text directory")
	flag.StringVar(&o.cache, "cache", ".cache/presets", "source archive cache")
	flag.StringVar(&o.sourceRoot, "source-root", "", "use extracted sources from this directory instead of network")
	flag.BoolVar(&o.check, "check", false, "verify generated files without writing them")
	flag.BoolVar(&o.dnsEnabled, "dns", false, "verify newly added domains resolve")
	flag.BoolVar(&o.offline, "offline", false, "do not download missing source archives")
	flag.Parse()
	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "presets:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	root, err := repoRoot()
	if err != nil {
		return err
	}
	r, err := loadRecipe(o.recipe)
	if err != nil {
		return err
	}
	base, err := loadCatalog(o.base)
	if err != nil {
		return err
	}
	snap, err := loadSnapshot(o.snapshot)
	if err != nil {
		return err
	}
	sources, lockSources, err := loadSources(root, o, r)
	if err != nil {
		return err
	}
	managed, order, err := compose(r, sources, &snap, o.check)
	if err != nil {
		return err
	}
	out := make([]preset, 0, len(order))
	for _, id := range order {
		out = append(out, managed[id])
	}
	raw, err := marshalCatalog(out)
	if err != nil {
		return err
	}
	lock := lockFile{Schema: 1, Sources: lockSources, OutputSHA256: hashBytes(raw)}
	lockRaw, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	lockRaw = append(lockRaw, '\n')
	snapRaw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	snapRaw = append(snapRaw, '\n')
	notices, err := renderNotices(r, lockSources)
	if err != nil {
		return err
	}
	sourcesDoc := []byte("# Preset sources\n\n" + renderSourcesBlock(r, lockSources))
	if o.dnsEnabled {
		if err := checkAddedDomains(base, out); err != nil {
			return err
		}
	}
	if o.check {
		return checkOutputs(o, raw, lockRaw, snapRaw, notices, sourcesDoc, sources)
	}
	if err := writeOutputs(o, raw, lockRaw, snapRaw, notices, sourcesDoc, sources); err != nil {
		return err
	}
	fmt.Printf("generated %d presets\n", len(out))
	return nil
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

func loadRecipe(path string) (*recipe, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r recipe
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("recipe: %w", err)
	}
	if r.Schema != 1 {
		return nil, fmt.Errorf("recipe schema: %d", r.Schema)
	}
	allowedLicenses := map[string]bool{
		"MIT": true, "BSD-2-Clause": true, "BSD-3-Clause": true, "Apache-2.0": true,
		"ISC": true, "0BSD": true, "CC0-1.0": true, "Unlicense": true,
		"GPL-2.0-only": true, "GPL-2.0-or-later": true,
		"GPL-3.0-only": true, "GPL-3.0-or-later": true,
	}
	for name, src := range r.Sources {
		if !allowedLicenses[src.License] {
			return nil, fmt.Errorf("source %s: license %q is not allowed", name, src.License)
		}
		location := strings.ToLower(src.Repo + " " + src.Archive)
		if strings.Contains(location, "kvaspro.su") {
			return nil, fmt.Errorf("source %s: denied host kvaspro.su", name)
		}
		switch src.Kind {
		case "local":
			if src.Origin != "project" || src.License != "GPL-3.0-only" {
				return nil, fmt.Errorf("source %s: local sources must be project-owned GPL-3.0-only", name)
			}
			if src.LicensePath == "" {
				return nil, fmt.Errorf("source %s: license_path is required", name)
			}
		case "github":
			if src.Revision == "" || src.Archive == "" || src.ArchiveSHA256 == "" || src.LicensePath == "" || src.LicenseSHA256 == "" {
				return nil, fmt.Errorf("source %s: pinned revision, archive hash, and license hash are required", name)
			}
			if !strings.Contains(src.Archive, "{revision}") {
				return nil, fmt.Errorf("source %s: archive URL must use {revision}", name)
			}
		default:
			return nil, fmt.Errorf("source %s: unsupported kind %q", name, src.Kind)
		}
	}
	seen := map[string]bool{}
	for _, p := range r.Presets {
		if p.ID == "" || seen[p.ID] {
			return nil, fmt.Errorf("recipe preset id %q is empty or duplicated", p.ID)
		}
		seen[p.ID] = true
		if len(p.Parts) == 0 {
			return nil, fmt.Errorf("preset %s has no parts", p.ID)
		}
		for _, domains := range [][]string{p.Exclude, p.ExcludeSubtrees} {
			if err := validateFilters(p.ID, domains); err != nil {
				return nil, err
			}
		}
		for _, part := range p.Parts {
			if _, ok := r.Sources[part.Source]; !ok {
				return nil, fmt.Errorf("preset %s references unknown source %s", p.ID, part.Source)
			}
			if len(part.Files) == 0 {
				return nil, fmt.Errorf("preset %s source %s has no files", p.ID, part.Source)
			}
			if err := validateFilters(p.ID, part.Only); err != nil {
				return nil, err
			}
		}
	}
	return &r, nil
}

func validateFilters(preset string, domains []string) error {
	for _, domain := range domains {
		if domain == "" || normalizeDomain(domain) != domain {
			return fmt.Errorf("preset %s: non-canonical domain filter %q", preset, domain)
		}
	}
	return nil
}

func loadCatalog(path string) ([]preset, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []preset
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func loadSnapshot(path string) (snapshotFile, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshotFile{Schema: 1, Files: map[string]snapshotEntry{}}, nil
	}
	if err != nil {
		return snapshotFile{}, err
	}
	var s snapshotFile
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, err
	}
	if s.Files == nil {
		s.Files = map[string]snapshotEntry{}
	}
	s.Schema = 1
	return s, nil
}

func loadSources(root string, o options, r *recipe) (map[string]*loadedSource, map[string]lockSource, error) {
	loaded := map[string]*loadedSource{}
	locked := map[string]lockSource{}
	for name, spec := range r.Sources {
		var srcRoot string
		if o.sourceRoot != "" {
			candidate := filepath.Join(o.sourceRoot, name)
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				srcRoot = candidate
			}
		}
		if srcRoot == "" {
			switch spec.Kind {
			case "local":
				base := o.sourceRoot
				if base == "" {
					base = filepath.Join(root, "tools/presets/data")
				}
				srcRoot = base
			case "github":
				var err error
				srcRoot, err = fetchSource(root, o, name, spec)
				if err != nil {
					return nil, nil, err
				}
			default:
				return nil, nil, fmt.Errorf("source %s: unsupported kind %q", name, spec.Kind)
			}
		}
		licensePath := spec.LicensePath
		if spec.Kind == "local" {
			licensePath = filepath.Join(root, spec.LicensePath)
		} else {
			licensePath = filepath.Join(srcRoot, spec.LicensePath)
		}
		licenseText, err := os.ReadFile(licensePath)
		if err != nil {
			return nil, nil, fmt.Errorf("source %s license: %w", name, err)
		}
		if spec.LicenseSHA256 != "" && hashBytes(licenseText) != spec.LicenseSHA256 {
			return nil, nil, fmt.Errorf("source %s license hash mismatch", name)
		}
		loaded[name] = &loadedSource{name: name, spec: spec, root: srcRoot, licenseText: licenseText}
		url := spec.Archive
		revision := spec.Revision
		if spec.Kind == "local" {
			url = "project-owned seed"
			revision = "working tree"
		} else {
			url = strings.ReplaceAll(url, "{revision}", spec.Revision)
		}
		var files []string
		for _, p := range r.Presets {
			for _, part := range p.Parts {
				if part.Source == name {
					files = append(files, part.Files...)
				}
			}
		}
		files = sortUnique(files)
		locked[name] = lockSource{
			URL: url, Revision: revision, ArchiveSHA256: spec.ArchiveSHA256,
			License: spec.License, LicenseSHA256: spec.LicenseSHA256,
			LicenseFile: "LICENSES/" + name + ".txt", Files: files,
		}
	}
	return loaded, locked, nil
}

func fetchSource(root string, o options, name string, spec source) (string, error) {
	cache := o.cache
	if !filepath.IsAbs(cache) {
		cache = filepath.Join(root, cache)
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		return "", err
	}
	archive := filepath.Join(cache, name+"-"+spec.Revision+".tar.gz")
	if _, err := os.Stat(archive); errors.Is(err, os.ErrNotExist) {
		if o.offline {
			return "", fmt.Errorf("source %s archive missing in offline mode", name)
		}
		url := strings.ReplaceAll(spec.Archive, "{revision}", spec.Revision)
		if err := download(url, archive); err != nil {
			return "", fmt.Errorf("source %s download: %w", name, err)
		}
	}
	raw, err := os.ReadFile(archive)
	if err != nil {
		return "", err
	}
	if spec.ArchiveSHA256 != "" && hashBytes(raw) != spec.ArchiveSHA256 {
		return "", fmt.Errorf("source %s archive hash mismatch", name)
	}
	extract := filepath.Join(cache, name+"-"+spec.Revision)
	marker := filepath.Join(extract, ".complete")
	if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
		if err := os.RemoveAll(extract); err != nil {
			return "", err
		}
		if err := extractArchive(archive, extract); err != nil {
			return "", fmt.Errorf("source %s extract: %w", name, err)
		}
		if err := os.WriteFile(marker, []byte("ok\n"), 0o644); err != nil {
			return "", err
		}
	}
	return extract, nil
}

func download(url, path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(resp.Body, 256<<20)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func extractArchive(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		if name == "." || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("unsafe archive path %q", hdr.Name)
		}
		parts := strings.Split(name, string(filepath.Separator))
		if len(parts) < 2 {
			continue
		}
		rel := filepath.Join(parts[1:]...)
		target := filepath.Join(dest, rel)
		if !strings.HasPrefix(target, dest+string(filepath.Separator)) && target != dest {
			return fmt.Errorf("unsafe archive path %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size > 64<<20 {
				return fmt.Errorf("archive member too large: %s", hdr.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, hdr.Size)); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}
}

func compose(r *recipe, sources map[string]*loadedSource, snap *snapshotFile, check bool) (map[string]preset, []string, error) {
	managed := map[string]preset{}
	order := make([]string, 0, len(r.Presets))
	for _, spec := range r.Presets {
		var domains []string
		for _, part := range spec.Parts {
			only := make(map[string]bool, len(part.Only))
			for _, domain := range part.Only {
				only[domain] = true
			}
			preserve := func(candidates []string) {
				if len(only) == 0 {
					domains = append(domains, candidates...)
					return
				}
				for _, domain := range candidates {
					if only[domain] {
						domains = append(domains, domain)
					}
				}
			}
			src := sources[part.Source]
			for _, file := range part.Files {
				newDomains, err := readDomains(src, file)
				key := part.Source + "\x00" + file
				old, hasOld := snap.Files[key]
				if err != nil {
					if hasOld {
						fmt.Fprintf(os.Stderr, "WARN source %s/%s unavailable: %v; preserving %d domains\n", part.Source, file, err, len(old.Domains))
						preserve(old.Domains)
						continue
					}
					return nil, nil, err
				}
				if hasOld && len(newDomains) < len(old.Domains) {
					merged := union(old.Domains, newDomains)
					fmt.Fprintf(os.Stderr, "WARN source %s/%s shrank from %d to %d domains; preserving %d domains\n", part.Source, file, len(old.Domains), len(newDomains), len(merged))
					snap.Files[key] = snapshotEntry{Source: part.Source, File: file, SourceCount: len(newDomains), Domains: merged}
					newDomains = merged
				} else {
					snap.Files[key] = snapshotEntry{Source: part.Source, File: file, SourceCount: len(newDomains), Domains: newDomains}
				}
				preserve(newDomains)
			}
		}
		domains = sortUnique(domains)
		if len(spec.Exclude) != 0 || len(spec.ExcludeSubtrees) != 0 {
			domains = slices.DeleteFunc(domains, func(domain string) bool {
				if slices.Contains(spec.Exclude, domain) {
					return true
				}
				for _, root := range spec.ExcludeSubtrees {
					if domain == root || strings.HasSuffix(domain, "."+root) {
						return true
					}
				}
				return false
			})
		}
		if len(domains) == 0 {
			return nil, nil, fmt.Errorf("preset %s has no domains", spec.ID)
		}
		managed[spec.ID] = preset{ID: spec.ID, Name: spec.Name, Category: spec.Category, Domains: domains, Prefixes: []string{}, Description: spec.Description}
		order = append(order, spec.ID)
	}
	return managed, order, nil
}

func readDomains(src *loadedSource, file string) ([]string, error) {
	path := filepath.Join(src.root, src.spec.Dir, file)
	switch src.spec.Format {
	case "v2fly":
		seen := map[string]bool{}
		return parseV2fly(path, seen)
	case "plain":
		return parsePlain(path, false)
	case "hosts":
		return parsePlain(path, true)
	default:
		return nil, fmt.Errorf("source %s: unsupported format %q", src.name, src.spec.Format)
	}
}

func parseV2fly(path string, seen map[string]bool) ([]string, error) {
	if seen[path] {
		return nil, nil
	}
	seen[path] = true
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 1 {
			continue
		}
		entry := fields[0]
		switch {
		case strings.HasPrefix(entry, "include:"):
			included, err := parseV2fly(filepath.Join(filepath.Dir(path), strings.TrimPrefix(entry, "include:")), seen)
			if err != nil {
				return nil, err
			}
			out = append(out, included...)
		case strings.HasPrefix(entry, "domain:"):
			out = append(out, entry)
		case strings.HasPrefix(entry, "full:"), strings.HasPrefix(entry, "regexp:"), strings.HasPrefix(entry, "keyword:"):
			continue
		default:
			out = append(out, entry)
		}
	}
	return normalizeAll(out), nil
}

func parsePlain(path string, hosts bool) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if hosts {
			if len(fields) < 2 {
				continue
			}
			out = append(out, fields[len(fields)-1])
			continue
		}
		if len(fields) == 1 {
			out = append(out, fields[0])
		}
	}
	return normalizeAll(out), nil
}

func normalizeAll(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if strings.HasPrefix(s, "domain:") {
			s = strings.TrimPrefix(s, "domain:")
		}
		if !strings.Contains(s, ".") {
			continue
		}
		if domain := normalizeDomain(s); domain != "" {
			out = append(out, domain)
		}
	}
	return sortUnique(out)
}

func normalizeDomain(raw string) string {
	raw = strings.TrimPrefix(strings.TrimPrefix(raw, "*."), ".")
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(raw, "."))
	if err != nil || !strings.Contains(ascii, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return ""
	}
	return strings.ToLower(ascii)
}

func sortUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func union(a, b []string) []string {
	return sortUnique(append(append([]string{}, a...), b...))
}

func marshalCatalog(p []preset) ([]byte, error) {
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func renderSourcesBlock(r *recipe, locked map[string]lockSource) string {
	var b strings.Builder
	b.WriteString("## Generated preset sources\n\n")
	b.WriteString("Presets are generated from the sources below. License texts are under `LICENSES/` inside the notices archive.\n\n")
	b.WriteString("| Source | URL | Revision | License |\n|---|---|---|---|\n")
	names := make([]string, 0, len(locked))
	for name := range locked {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := locked[name]
		b.WriteString(fmt.Sprintf("| `%s` | %s | `%s` | %s |\n", name, s.URL, s.Revision, s.License))
	}
	b.WriteString("\n| Preset | Sources |\n|---|---|\n")
	for _, p := range r.Presets {
		var parts []string
		for _, part := range p.Parts {
			parts = append(parts, fmt.Sprintf("`%s` (%s)", part.Source, strings.Join(part.Files, ", ")))
		}
		b.WriteString(fmt.Sprintf("| `%s` | %s |\n", p.ID, strings.Join(parts, "; ")))
	}
	b.WriteString("\n")
	return b.String()
}

func renderNotices(r *recipe, locked map[string]lockSource) ([]byte, error) {
	raw, err := os.ReadFile("THIRD_PARTY_NOTICES.md")
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimRight(string(raw), "\n") + "\n\n" + renderSourcesBlock(r, locked)), nil
}

func writeOutputs(o options, presets, lock, snapshot, notices, sourcesDoc []byte, sources map[string]*loadedSource) error {
	if err := os.MkdirAll(filepath.Dir(o.out), 0o755); err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		data []byte
	}{{o.out, presets}, {o.lock, lock}, {o.snapshotOut, snapshot}, {o.notices, notices}, {o.sourcesDoc, sourcesDoc}} {
		if err := os.MkdirAll(filepath.Dir(item.path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(item.path, item.data, 0o644); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(o.licenses, 0o755); err != nil {
		return err
	}
	for name, src := range sources {
		if err := os.WriteFile(filepath.Join(o.licenses, name+".txt"), src.licenseText, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func checkOutputs(o options, presets, lock, snapshot, notices, sourcesDoc []byte, sources map[string]*loadedSource) error {
	for _, item := range []struct {
		path string
		data []byte
	}{{o.out, presets}, {o.lock, lock}, {o.snapshotOut, snapshot}, {o.notices, notices}, {o.sourcesDoc, sourcesDoc}} {
		old, err := os.ReadFile(item.path)
		if err != nil {
			return fmt.Errorf("%s: %w", item.path, err)
		}
		if !bytes.Equal(old, item.data) {
			return fmt.Errorf("%s is stale; run go run ./tools/presets", item.path)
		}
	}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(o.licenses, name+".txt")
		old, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if !bytes.Equal(old, []byte(sources[name].licenseText)) {
			return fmt.Errorf("%s is stale; run go run ./tools/presets", path)
		}
	}
	fmt.Println("preset catalog is up to date")
	return nil
}

func checkAddedDomains(base, out []preset) error {
	old := map[string]map[string]bool{}
	for _, p := range base {
		old[p.ID] = map[string]bool{}
		for _, d := range p.Domains {
			old[p.ID][d] = true
		}
	}
	added := map[string]bool{}
	for _, p := range out {
		for _, d := range p.Domains {
			if !old[p.ID][d] {
				added[d] = true
			}
		}
	}
	if len(added) == 0 {
		fmt.Println("DNS: no added domains")
		return nil
	}
	domains := make([]string, 0, len(added))
	for d := range added {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return dnsCheck(domains)
}

func dnsCheck(domains []string) error {
	servers := []string{"1.1.1.1:53", "9.9.9.9:53"}
	type result struct {
		domain string
		status string
		err    error
	}
	results := make(chan result, len(domains))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for _, domain := range domains {
		if !strings.Contains(domain, ".") {
			results <- result{domain: domain, status: "skip"}
			continue
		}
		domain := domain
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			status, err := dnsOne(domain, servers)
			results <- result{domain: domain, status: status, err: err}
		}()
	}
	wg.Wait()
	close(results)
	counts := map[string]int{}
	var failures []string
	for r := range results {
		counts[r.status]++
		if r.status == "NXDOMAIN" || r.status == "ERROR" {
			detail := r.domain + " (" + r.status + ")"
			if r.err != nil {
				detail += ": " + r.err.Error()
			}
			failures = append(failures, detail)
		}
	}
	fmt.Printf("DNS: %d added domains, %v\n", len(domains), counts)
	if len(failures) > 0 {
		sort.Strings(failures)
		limit := len(failures)
		if limit > 10 {
			limit = 10
		}
		return fmt.Errorf("DNS verification failed for %d domains: %v", len(failures), failures[:limit])
	}
	return nil
}

func dnsOne(domain string, servers []string) (string, error) {
	var lastErr error
	sawNoError, sawNX := false, false
	for _, server := range servers {
		c := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), qtype)
			m.RecursionDesired = true
			var r *dns.Msg
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				r, _, err = c.Exchange(m.Copy(), server)
				if err == nil {
					break
				}
				lastErr = err
			}
			if r == nil {
				continue
			}
			if len(r.Answer) > 0 {
				return "OK", nil
			}
			switch r.Rcode {
			case dns.RcodeSuccess:
				sawNoError = true
			case dns.RcodeNameError:
				sawNX = true
			}
		}
	}
	if sawNoError {
		return "NODATA", nil
	}
	if sawNX {
		return "NXDOMAIN", nil
	}
	return "ERROR", lastErr
}

func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
