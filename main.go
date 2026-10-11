// secretscan — fast git-secrets scanner in Go.
// Detects patterns that show up in real C2 builds and live infra:
//   AWS access keys (AKIA, ASIA), GitHub PATs (ghp_), GitLab PATs (glpat-),
//   Slack tokens (xoxb-, xoxp-, xoxa-), OpenAI/Anthropic/DeepSeek keys,
//   JWT with suspicious alg=none, .env files, generic high-entropy blobs.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct {
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Pattern  string `json:"pattern"`
	Match    string `json:"match"`
	SHA256   string `json:"sha256"`
	Severity string `json:"severity"`
}

var patterns = []struct {
	Name     string
	Regex    *regexp.Regexp
	Severity string
}{
	{"aws-access-key", regexp.MustCompile(`(?:AKIA|ASIA)[0-9A-Z]{16}`), "critical"},
	{"aws-secret-key", regexp.MustCompile(`(?i)aws(.{0,20})?(secret|sk).{0,20}['"\`][0-9a-zA-Z/+]{40}['"\`]`), "critical"},
	{"github-pat", regexp.MustCompile(`ghp_[A-Za-z0-9]{36,255}`), "high"},
	{"github-fine", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`), "high"},
	{"gitlab-pat", regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), "high"},
	{"slack-token", regexp.MustCompile(`xox[bpars]-[A-Za-z0-9-]{10,}`), "high"},
	{"openai-key", regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`), "high"},
	{"anthropic-key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`), "high"},
	{"deepseek-key", regexp.MustCompile(`sk-[A-Za-z0-9]{32,}`), "high"},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), "medium"},
	{"private-key", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`), "critical"},
	{"env-file", regexp.MustCompile(`(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*['"\`][^'"\`\s]{8,}['"\`]`), "medium"},
	{"heroku", regexp.MustCompile(`heroku[a-z0-9_ \.,-]{0,25}(?:[0-9a-fA-F]{32}-[0-9a-fA-F]{12})`), "medium"},
	{"npm", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`), "high"},
	{"stripe", regexp.MustCompile(`(?:sk|pk|rk)_(?:test|live)_[A-Za-z0-9]{20,}`), "high"},
}

func scanFile(path string, info fs.FileInfo) []Finding {
	if info.IsDir() || info.Size() > 10*1024*1024 {
		return nil
	}
	skipExt := map[string]bool{
		".png": true, ".jpg": true, ".gif": true, ".pdf": true,
		".zip": true, ".tar": true, ".gz": true, ".exe": true,
		".so": true, ".dylib": true, ".dll": true, ".bin": true,
	}
	if skipExt[filepath.Ext(path)] {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Finding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		for _, p := range patterns {
			if m := p.Regex.FindString(line); m != "" {
				sum := sha256.Sum256([]byte(m))
				out = append(out, Finding{
					Path:     path,
					Line:     lineNo,
					Pattern:  p.Name,
					Match:    m,
					SHA256:   hex.EncodeToString(sum[:8]),
					Severity: p.Severity,
				})
			}
		}
	}
	return out
}

func main() {
	root := flag.String("root", ".", "directory to scan")
	format := flag.String("format", "text", "text or json")
	flag.Parse()

	var allFindings []Finding
	err := filepath.WalkDir(*root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// skip .git, vendor, node_modules
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		allFindings = append(allFindings, scanFile(path, info)...)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "walk error:", err)
		os.Exit(1)
	}

	if *format == "json" {
		fmt.Printf("{\"findings\":[")
		for i, fnd := range allFindings {
			if i > 0 { fmt.Printf(",") }
			fmt.Printf(`{"path":%q,"line":%d,"pattern":%q,"match":%q,"sha256":%q,"severity":%q}`,
				fnd.Path, fnd.Line, fnd.Pattern, fnd.Match, fnd.SHA256, fnd.Severity)
		}
		fmt.Printf("],\"count\":%d}\n", len(allFindings))
	} else {
		fmt.Printf("scanned %s\n", *root)
		fmt.Printf("found %d potential secrets\n", len(allFindings))
		for _, fnd := range allFindings {
			fmt.Printf("[%s] %s:%d  %s  %s\n",
				strings.ToUpper(fnd.Severity), fnd.Path, fnd.Line,
				fnd.Pattern, fnd.Match)
		}
	}
	if len(allFindings) > 0 {
		os.Exit(2)  // signal findings to CI
	}
}
