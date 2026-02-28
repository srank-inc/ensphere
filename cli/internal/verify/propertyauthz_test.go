package verify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestVerifyPropertyAuthZ_FieldDifference(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if auth == "Bearer admin-token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "Alice", "email": "a@test.com", "ssn": "123-45-6789", "salary": 100000,
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "Alice", "email": "a@test.com",
			})
		}
	}))

	cfg := PropertyAuthZConfig{
		URL:           srv.URL + "/api/user",
		Method:        "GET",
		HighPrivToken: "admin-token",
		LowPrivToken:  "user-token",
		ProbeConfig:   baseProbeConfig(),
	}

	result, err := VerifyPropertyAuthZ(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := result.Measurements.(PropertyAuthZMeasurements)
	if len(m.SharedFields) != 3 {
		t.Errorf("expected 3 shared fields, got %d: %v", len(m.SharedFields), m.SharedFields)
	}
	if len(m.HighPrivOnlyFields) != 2 {
		t.Errorf("expected 2 high-priv-only fields, got %d: %v", len(m.HighPrivOnlyFields), m.HighPrivOnlyFields)
	}
	if len(m.LowPrivOnlyFields) != 0 {
		t.Errorf("expected 0 low-priv-only fields, got %d: %v", len(m.LowPrivOnlyFields), m.LowPrivOnlyFields)
	}
	if m.HashesMatch {
		t.Error("expected hashes to not match")
	}
}

func TestVerifyPropertyAuthZ_IdenticalResponses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":1,"name":"Alice"}`)
	}))

	cfg := PropertyAuthZConfig{
		URL:           srv.URL + "/api/user",
		Method:        "GET",
		HighPrivToken: "admin-token",
		LowPrivToken:  "user-token",
		ProbeConfig:   baseProbeConfig(),
	}

	result, err := VerifyPropertyAuthZ(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := result.Measurements.(PropertyAuthZMeasurements)
	if !m.HashesMatch {
		t.Error("expected hashes to match for identical responses")
	}
	if len(m.HighPrivOnlyFields) != 0 {
		t.Errorf("expected 0 high-priv-only fields, got %v", m.HighPrivOnlyFields)
	}
}

func TestVerifyPropertyAuthZ_WatchFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		if auth == "Bearer admin-token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "Alice", "ssn": "123-45-6789",
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id": 1, "name": "Alice",
			})
		}
	}))

	cfg := PropertyAuthZConfig{
		URL:           srv.URL + "/api/user",
		Method:        "GET",
		HighPrivToken: "admin-token",
		LowPrivToken:  "user-token",
		WatchFields:   []string{"ssn", "name", "secret"},
		ProbeConfig:   baseProbeConfig(),
	}

	result, err := VerifyPropertyAuthZ(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := result.Measurements.(PropertyAuthZMeasurements)
	if len(m.WatchFieldResults) != 3 {
		t.Fatalf("expected 3 watch results, got %d", len(m.WatchFieldResults))
	}

	for _, w := range m.WatchFieldResults {
		switch w.Name {
		case "ssn":
			if !w.InHighPriv || w.InLowPriv {
				t.Errorf("ssn: expected in_high=true, in_low=false; got %v, %v", w.InHighPriv, w.InLowPriv)
			}
		case "name":
			if !w.InHighPriv || !w.InLowPriv {
				t.Errorf("name: expected in both; got %v, %v", w.InHighPriv, w.InLowPriv)
			}
		case "secret":
			if w.InHighPriv || w.InLowPriv {
				t.Errorf("secret: expected in neither; got %v, %v", w.InHighPriv, w.InLowPriv)
			}
		}
	}
}

func TestVerifyPropertyAuthZ_NonJSONResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	srv := newTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>Hello</body></html>")
	}))

	cfg := PropertyAuthZConfig{
		URL:           srv.URL + "/page",
		Method:        "GET",
		HighPrivToken: "admin-token",
		LowPrivToken:  "user-token",
		ProbeConfig:   baseProbeConfig(),
	}

	result, err := VerifyPropertyAuthZ(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m := result.Measurements.(PropertyAuthZMeasurements)
	if m.HighPrivFields != nil {
		t.Errorf("expected nil high-priv fields for HTML, got %v", m.HighPrivFields)
	}
	if m.LowPrivFields != nil {
		t.Errorf("expected nil low-priv fields for HTML, got %v", m.LowPrivFields)
	}
}
