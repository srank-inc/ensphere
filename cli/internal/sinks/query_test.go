package sinks

import (
	"regexp"
	"testing"
)

func TestListCategoriesSortedAndPopulated(t *testing.T) {
	out, err := ListCategories()
	if err != nil {
		t.Fatalf("ListCategories: %v", err)
	}
	if len(out.Categories) == 0 {
		t.Fatal("expected at least one category")
	}
	for i := 1; i < len(out.Categories); i++ {
		if out.Categories[i-1].Name > out.Categories[i].Name {
			t.Fatalf("categories are not sorted: %s before %s", out.Categories[i-1].Name, out.Categories[i].Name)
		}
	}
}

func TestGetCategoryAndInvalidCategory(t *testing.T) {
	cat, err := GetCategory("sqli")
	if err != nil {
		t.Fatalf("GetCategory: %v", err)
	}
	if cat.Category != "sqli" || cat.Count == 0 || len(cat.Patterns) == 0 {
		t.Fatalf("unexpected category: %+v", cat)
	}
	if _, err := GetCategory("missing"); err == nil {
		t.Fatal("expected invalid category error")
	}
}

func TestEmbeddedRegexesCompile(t *testing.T) {
	patterns, err := AllPatterns()
	if err != nil {
		t.Fatalf("AllPatterns: %v", err)
	}
	for category, entries := range patterns {
		for _, p := range entries {
			if _, err := regexp.Compile(p.Pattern); err != nil {
				t.Fatalf("%s/%s regex does not compile: %v", category, p.Name, err)
			}
		}
	}

	absenceRules, err := AllAbsenceRules()
	if err != nil {
		t.Fatalf("AllAbsenceRules: %v", err)
	}
	for category, entries := range absenceRules {
		for _, r := range entries {
			if _, err := regexp.Compile(r.Pattern); err != nil {
				t.Fatalf("%s/%s absence regex does not compile: %v", category, r.Name, err)
			}
			if _, err := regexp.Compile(r.SecurityPattern); err != nil {
				t.Fatalf("%s/%s security regex does not compile: %v", category, r.Name, err)
			}
		}
	}
}
