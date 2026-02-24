package templates

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Materialize writes all template files to outDir. If outDir is empty, prints to w.
func Materialize(name string, outDir string, w io.Writer) error {
	cfg, err := loadConfig(name)
	if err != nil {
		return err
	}

	if outDir != "" {
		return materializeToDir(cfg, outDir)
	}
	return materializeToWriter(cfg, w)
}

func materializeToDir(cfg *TemplateConfig, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	for _, file := range cfg.Files {
		data, err := fs.ReadFile(embeddedData, "data/"+cfg.Name+"/"+file)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", file, err)
		}

		dst := filepath.Join(outDir, file)
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", dst, err)
		}
	}

	// Also write template.json for reference
	configData, err := fs.ReadFile(embeddedData, "data/"+cfg.Name+"/template.json")
	if err != nil {
		return fmt.Errorf("read template.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "template.json"), configData, 0644); err != nil {
		return fmt.Errorf("write template.json: %w", err)
	}

	return nil
}

func materializeToWriter(cfg *TemplateConfig, w io.Writer) error {
	for i, file := range cfg.Files {
		if i > 0 {
			fmt.Fprintf(w, "\n--- %s ---\n\n", file)
		} else {
			fmt.Fprintf(w, "--- %s ---\n\n", file)
		}

		data, err := fs.ReadFile(embeddedData, "data/"+cfg.Name+"/"+file)
		if err != nil {
			return fmt.Errorf("read embedded %s: %w", file, err)
		}
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("write %s: %w", file, err)
		}
	}
	return nil
}
