package sinks

import (
	"fmt"
	"io/fs"
	"sort"
	"sync"

	"gopkg.in/yaml.v3"
)

// sinksFile is the intermediate struct for YAML parsing.
type sinksFile struct {
	Categories   map[string][]SinkPattern `yaml:"categories"`
	AbsenceRules map[string][]AbsenceRule `yaml:"absence_rules"`
}

var (
	parsedData *sinksFile
	parseOnce  sync.Once
	parseErr   error
)

// load parses the embedded YAML file once and caches the result.
func load() (*sinksFile, error) {
	parseOnce.Do(func() {
		raw, err := fs.ReadFile(embeddedData, "data/sinks.yaml")
		if err != nil {
			parseErr = fmt.Errorf("read embedded sinks data: %w", err)
			return
		}
		var sf sinksFile
		if err := yaml.Unmarshal(raw, &sf); err != nil {
			parseErr = fmt.Errorf("parse sinks YAML: %w", err)
			return
		}
		parsedData = &sf
	})
	return parsedData, parseErr
}

// ListCategories returns a summary of all sink categories.
func ListCategories() (*SinkListOutput, error) {
	data, err := load()
	if err != nil {
		return nil, err
	}

	names := sortedKeys(data.Categories)
	summaries := make([]SinkSummary, 0, len(names))
	for _, name := range names {
		summaries = append(summaries, SinkSummary{
			Name:         name,
			PatternCount: len(data.Categories[name]),
		})
	}

	return &SinkListOutput{Categories: summaries}, nil
}

// GetCategory returns patterns for a specific category.
func GetCategory(name string) (*SinkCategory, error) {
	data, err := load()
	if err != nil {
		return nil, err
	}

	patterns, ok := data.Categories[name]
	if !ok {
		return nil, fmt.Errorf("category %q not found", name)
	}

	return &SinkCategory{
		Category: name,
		Count:    len(patterns),
		Patterns: patterns,
	}, nil
}

// CategoryNames returns a sorted list of valid category names.
func CategoryNames() []string {
	data, err := load()
	if err != nil {
		return nil
	}
	return sortedKeys(data.Categories)
}

// AllPatterns returns all sink patterns grouped by category.
func AllPatterns() (map[string][]SinkPattern, error) {
	data, err := load()
	if err != nil {
		return nil, err
	}
	return data.Categories, nil
}

// AllAbsenceRules returns all IaC absence rules grouped by category.
func AllAbsenceRules() (map[string][]AbsenceRule, error) {
	data, err := load()
	if err != nil {
		return nil, err
	}
	return data.AbsenceRules, nil
}

// sortedKeys returns the map keys in sorted order.
func sortedKeys(m map[string][]SinkPattern) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
