package templates

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
)

// ListTemplates reads all template.json files from embedded data and returns summaries.
func ListTemplates() ([]TemplateSummary, error) {
	entries, err := fs.ReadDir(embeddedData, "data")
	if err != nil {
		return nil, fmt.Errorf("read template data dir: %w", err)
	}

	var summaries []TemplateSummary
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		cfg, err := loadConfig(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("load template %s: %w", entry.Name(), err)
		}
		summaries = append(summaries, TemplateSummary{
			Name:        cfg.Name,
			Description: cfg.Description,
			VulnType:    cfg.VulnType,
			Technique:   cfg.Technique,
			Risk:        cfg.Risk,
			ParamCount:  len(cfg.Params),
			RunCommand:  cfg.RunCommand,
		})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })
	return summaries, nil
}

// GetTemplate loads a single template config by name.
func GetTemplate(name string) (*TemplateConfig, error) {
	return loadConfig(name)
}

// TemplateNames returns sorted list of available template names.
func TemplateNames() ([]string, error) {
	entries, err := fs.ReadDir(embeddedData, "data")
	if err != nil {
		return nil, fmt.Errorf("read template data dir: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func loadConfig(name string) (*TemplateConfig, error) {
	data, err := fs.ReadFile(embeddedData, "data/"+name+"/template.json")
	if err != nil {
		return nil, fmt.Errorf("read template.json: %w", err)
	}
	var cfg TemplateConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse template.json: %w", err)
	}
	if len(cfg.ObservationFields) == 0 {
		return nil, fmt.Errorf("parse template.json: observation_fields is required")
	}
	return &cfg, nil
}
