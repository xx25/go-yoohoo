package yoohoo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestReadmeUsageCompiles builds the program in README.md's Usage
// section against this checkout, so the documented API cannot drift
// from the real one.
func TestReadmeUsageCompiles(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, found := strings.Cut(string(readme), "```go\n")
	if !found {
		t.Fatal("README.md has no go code block")
	}
	src, _, found := strings.Cut(rest, "\n```")
	if !found {
		t.Fatal("README.md go code block is not closed")
	}
	here, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	gomod := "module readmeusage\n\ngo 1.25\n\nrequire github.com/xx25/go-yoohoo v0.0.0\n\nreplace github.com/xx25/go-yoohoo => " + strconv.Quote(here) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goBin, "vet", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("README usage does not compile: %v\n%s", err, out)
	}
}
