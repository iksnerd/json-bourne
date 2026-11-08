package config

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/iksnerd/json-bourne/internal/casefile"
	"gopkg.in/yaml.v3"
)

// caseCommands is the closed set of names a config may list under `commands:`: the
// commands that take --case, read a config and choose one with ChooseCaseConfig.
// `jb doctor` is not in it: without --config it checks every listed config.
var caseCommands = []string{"activity", "actor", "estate", "hunt", "intel", "rename-source", "serve", "watch"}

// checkCommands refuses a name outside the closed set, an empty name and a repeat.
func checkCommands(list []string) error {
	seen := map[string]bool{}
	for _, n := range list {
		if !slices.Contains(caseCommands, n) {
			return fmt.Errorf("commands: %q is not a command a config can be for; use one of: %s", n, strings.Join(caseCommands, ", "))
		}
		if seen[n] {
			return fmt.Errorf("commands: %q is listed twice", n)
		}
		seen[n] = true
	}
	return nil
}

// LoadCommands reads only the `commands:` key of the config at path. It ignores every
// other key, builds no adapter and reads no environment variable, so choosing among a
// case's configs stays cheap and cannot fail on a credential.
func LoadCommands(path string) ([]string, error) {
	fh, err := os.Open(path) // #nosec G304 -- a config listed by the case, confined by casefile
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("config %s is larger than %d bytes", path, maxFileSize)
	}
	if err := casefile.CheckYAMLShape("config", data); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	var head struct {
		Commands []string `yaml:"commands"`
	}
	if err := yaml.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := checkCommands(head.Commands); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return head.Commands, nil
}
