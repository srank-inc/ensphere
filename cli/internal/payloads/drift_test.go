package payloads

import (
	"sort"
	"testing"

	"github.com/srank/ensphere/internal/enums"
)

// Canary values: these counts are tied to docs (README.md, ENSPHERE-GO-SPEC.md,
// ENSPHERE-FULL-KALI-COVERAGE.md). When payloads are added or removed, update
// both this test AND the documentation.
const expectedPayloadCount = 1188
const expectedVulnTypeCount = 26

func TestPayloadCount_MatchesDocs(t *testing.T) {
	db, cleanup, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(cleanup)

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM payloads").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != expectedPayloadCount {
		t.Fatalf("payload count %d != expected %d — update this test AND docs if payloads changed", count, expectedPayloadCount)
	}
}

func TestVulnTypeCount_MatchesDocs(t *testing.T) {
	db, cleanup, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(cleanup)

	var count int
	err = db.QueryRow("SELECT COUNT(DISTINCT vuln_type) FROM payloads").Scan(&count)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != expectedVulnTypeCount {
		t.Fatalf("vuln type count %d != expected %d — update this test AND docs if types changed", count, expectedVulnTypeCount)
	}
}

func TestVulnTypesAreValid(t *testing.T) {
	db, cleanup, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(cleanup)

	rows, err := db.Query("SELECT DISTINCT vuln_type FROM payloads ORDER BY vuln_type")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()

	var dbTypes []string
	for rows.Next() {
		var vt string
		if err := rows.Scan(&vt); err != nil {
			t.Fatalf("scan: %v", err)
		}
		dbTypes = append(dbTypes, vt)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	if len(dbTypes) != expectedVulnTypeCount {
		t.Fatalf("expected %d distinct vuln types, got %d: %v", expectedVulnTypeCount, len(dbTypes), dbTypes)
	}

	// Every DB type must be a key in enums.ValidVulnTypes (DB ⊂ enums)
	for _, vt := range dbTypes {
		if !enums.ValidVulnTypes[vt] {
			t.Errorf("DB vuln_type %q not found in enums.ValidVulnTypes", vt)
		}
	}

	// Assert exact list matches hardcoded expected set
	expected := []string{
		"auth_bypass", "authz", "cache_poisoning", "cmdi", "cors", "csrf",
		"csv_injection", "deserialization", "file_upload", "graphql",
		"header_injection", "idor", "jwt", "ldap", "lfi", "nosql",
		"prototype_pollution", "race_condition", "redirect",
		"request_smuggling", "sqli", "ssrf", "ssti", "xpath", "xss", "xxe",
	}
	sort.Strings(dbTypes)
	sort.Strings(expected)

	if len(dbTypes) != len(expected) {
		t.Fatalf("set size mismatch: DB has %d, expected %d", len(dbTypes), len(expected))
	}
	for i := range expected {
		if dbTypes[i] != expected[i] {
			t.Errorf("mismatch at index %d: DB=%q expected=%q", i, dbTypes[i], expected[i])
		}
	}
}
