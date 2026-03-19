// Package goversion provides utilities to get the Go module version
// information.
package goversion

import (
	"cmp"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"
)

const unknown = "unknown"

// Info provides the version info.
type Info struct {
	GitVersion   string `json:"gitVersion"`
	ModuleSum    string `json:"moduleChecksum"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	BuiltBy      string `json:"builtBy"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`

	ASCIIName   string `json:"-"`
	Name        string `json:"-"`
	Description string `json:"-"`
	URL         string `json:"-"`
}

func getBuildInfo() *debug.BuildInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return bi
}

func getGitVersion(bi *debug.BuildInfo) string {
	if bi == nil {
		return ""
	}

	// TODO: remove this when the issue https://github.com/golang/go/issues/29228 is fixed
	if bi.Main.Version == "(devel)" || bi.Main.Version == "" {
		return ""
	}

	return bi.Main.Version
}

func getCommit(bi *debug.BuildInfo) string {
	return getKey(bi, "vcs.revision")
}

func getDirty(bi *debug.BuildInfo) string {
	modified := getKey(bi, "vcs.modified")
	if modified == "true" {
		return "dirty"
	}
	if modified == "false" {
		return "clean"
	}
	return ""
}

func getBuildDate(bi *debug.BuildInfo) string {
	buildTime := getKey(bi, "vcs.time")
	t, err := time.Parse("2006-01-02T15:04:05Z", buildTime)
	if err != nil {
		return ""
	}
	return t.Format("2006-01-02T15:04:05")
}

func getKey(bi *debug.BuildInfo, key string) string {
	if bi == nil {
		return ""
	}
	for _, iter := range bi.Settings {
		if iter.Key == key {
			return iter.Value
		}
	}
	return ""
}

// Option can be used to customize the version after its gathered from the
// environment.
type Option func(i *Info)

// WithAppDetails allows to set the app name and description.
func WithAppDetails(name, description, url string) Option {
	return func(i *Info) {
		i.Name = name
		i.Description = description
		i.URL = url
	}
}

// WithASCIIName allows you to add an ASCII art of the name.
func WithASCIIName(name string) Option {
	return func(i *Info) {
		i.ASCIIName = name
	}
}

// WithBuiltBy allows to set the builder name/builder system name.
func WithBuiltBy(name string) Option {
	return func(i *Info) {
		i.BuiltBy = name
	}
}

// TODO: write more WithXXX functions?

// GetVersionInfo represents known information on how this binary was built.
func GetVersionInfo(options ...Option) Info {
	buildInfo := getBuildInfo()
	i := Info{
		GitVersion:   cmp.Or(getGitVersion(buildInfo), "devel"),
		ModuleSum:    cmp.Or(buildInfo.Main.Sum, unknown),
		GitCommit:    cmp.Or(getCommit(buildInfo), unknown),
		GitTreeState: cmp.Or(getDirty(buildInfo), unknown),
		BuildDate:    cmp.Or(getBuildDate(buildInfo), unknown),
		BuiltBy:      unknown,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
	for _, opt := range options {
		opt(&i)
	}
	return i
}

// String returns the string representation of the version info
func (i Info) String() string {
	b := strings.Builder{}
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)

	// name and description are optional.
	if i.Name != "" {
		if i.ASCIIName != "" {
			_, _ = fmt.Fprint(w, i.ASCIIName)
		}
		_, _ = fmt.Fprint(w, i.Name)
		if i.Description != "" {
			_, _ = fmt.Fprintf(w, ": %s", i.Description)
		}
		if i.URL != "" {
			_, _ = fmt.Fprintf(w, "\n%s", i.URL)
		}
		_, _ = fmt.Fprint(w, "\n\n")
	}

	_, _ = fmt.Fprintf(w, "GitVersion:\t%s\n", i.GitVersion)
	_, _ = fmt.Fprintf(w, "GitCommit:\t%s\n", i.GitCommit)
	_, _ = fmt.Fprintf(w, "GitTreeState:\t%s\n", i.GitTreeState)
	_, _ = fmt.Fprintf(w, "BuildDate:\t%s\n", i.BuildDate)
	_, _ = fmt.Fprintf(w, "BuiltBy:\t%s\n", i.BuiltBy)
	_, _ = fmt.Fprintf(w, "GoVersion:\t%s\n", i.GoVersion)
	_, _ = fmt.Fprintf(w, "Compiler:\t%s\n", i.Compiler)
	_, _ = fmt.Fprintf(w, "ModuleSum:\t%s\n", i.ModuleSum)
	_, _ = fmt.Fprintf(w, "Platform:\t%s\n", i.Platform)

	_ = w.Flush()
	return b.String()
}

// JSONString returns the JSON representation of the version info
func (i *Info) JSONString() (string, error) {
	b, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}
