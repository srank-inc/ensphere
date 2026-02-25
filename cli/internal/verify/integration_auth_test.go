package verify

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestIntegration_Auth_NoToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t,authGateHandler("valid-token"))


	cfg := AuthConfig{
		URL:         ts.URL + "/api",
		Method:      "GET",
		Token:       "valid-token",
		Technique:   "no_token",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyAuth(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(AuthMeasurements)
	if !ok {
		t.Fatalf("expected AuthMeasurements, got %T", result.Measurements)
	}
	if m.Baseline.StatusCode != 200 {
		t.Fatalf("expected baseline status 200, got %d", m.Baseline.StatusCode)
	}
	if m.Probe.StatusCode != 401 {
		t.Fatalf("expected probe status 401, got %d", m.Probe.StatusCode)
	}
}

func TestIntegration_AuthZ(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t,http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer high-token" {
			w.WriteHeader(200)
			fmt.Fprint(w, `{"role":"admin","data":"secret"}`)
		} else {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"forbidden"}`)
		}
	}))


	cfg := AuthZConfig{
		URL:           ts.URL + "/admin",
		Method:        "GET",
		LowPrivToken:  "low-token",
		HighPrivToken: "high-token",
		ProbeConfig:   baseProbeConfig(),
	}

	result, err := VerifyAuthZ(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(AuthZMeasurements)
	if !ok {
		t.Fatalf("expected AuthZMeasurements, got %T", result.Measurements)
	}
	if m.HighPriv.StatusCode == m.LowPriv.StatusCode {
		t.Fatalf("expected different status codes, both got %d", m.HighPriv.StatusCode)
	}
}

func TestIntegration_RLS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	const jwtSecret = "test-secret-at-least-32-chars-long"

	ts := newTestServer(t,http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/rest/v1/") {
			w.WriteHeader(404)
			return
		}

		// Parse JWT from Authorization header
		auth := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(auth, "Bearer ")

		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil {
			w.WriteHeader(401)
			fmt.Fprintf(w, `{"error":"invalid token: %v"}`, err)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			w.WriteHeader(401)
			return
		}

		tokenCompanyID, _ := claims["company_id"].(string)
		queryCompanyID := r.URL.Query().Get("company_id")
		// Extract from "eq.VALUE"
		if strings.HasPrefix(queryCompanyID, "eq.") {
			queryCompanyID = strings.TrimPrefix(queryCompanyID, "eq.")
		}

		// Simulate RLS: only return rows if token company matches query company
		if tokenCompanyID == queryCompanyID {
			w.WriteHeader(200)
			fmt.Fprintf(w, `[{"id":1,"company_id":"%s","data":"row1"}]`, queryCompanyID)
		} else {
			w.WriteHeader(200)
			fmt.Fprint(w, `[]`)
		}
	}))


	cfg := RLSConfig{
		ProjectURL: ts.URL,
		AnonKey:    "test-anon-key",
		JWTSecret:  jwtSecret,
		Table:      "projects",
		TenantA:    "company-a",
		TenantB:    "company-b",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyRLS(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(RLSMeasurements)
	if !ok {
		t.Fatalf("expected RLSMeasurements, got %T", result.Measurements)
	}
	if m.TenantAOwn.StatusCode == 0 {
		t.Fatal("expected TenantAOwn.StatusCode > 0")
	}
	if m.TenantBOwn.StatusCode == 0 {
		t.Fatal("expected TenantBOwn.StatusCode > 0")
	}
	if m.CrossTenant.StatusCode == 0 {
		t.Fatal("expected CrossTenant.StatusCode > 0")
	}
}

func TestIntegration_JWT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	const validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	ts := newTestServer(t,authGateHandler(validToken))


	cfg := JWTConfig{
		URL:         ts.URL + "/api",
		Token:       validToken,
		Technique:   "alg_none",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyJWT(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(JWTMeasurements)
	if !ok {
		t.Fatalf("expected JWTMeasurements, got %T", result.Measurements)
	}
	if m.Baseline.StatusCode != 200 {
		t.Fatalf("expected baseline status 200, got %d", m.Baseline.StatusCode)
	}
	if m.ModifiedToken == "" {
		t.Fatal("expected non-empty ModifiedToken")
	}
}

func TestIntegration_CORS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t,http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))


	cfg := CORSConfig{
		URL:         ts.URL + "/api",
		Method:      "GET",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyCORS(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(CORSMeasurements)
	if !ok {
		t.Fatalf("expected CORSMeasurements, got %T", result.Measurements)
	}
	if !m.EvilOrigin.OriginReflected {
		t.Fatal("expected EvilOrigin.OriginReflected == true")
	}
}

func TestIntegration_CSRF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t,http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc123; SameSite=Lax; Secure")
		w.WriteHeader(200)
		fmt.Fprint(w, `<form><input type="hidden" name="csrf_token" value="xyz"></form>`)
	}))


	cfg := CSRFConfig{
		URL:         ts.URL + "/form",
		Method:      "POST",
		ProbeConfig: baseProbeConfig(),
	}

	result, err := VerifyCSRF(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(CSRFMeasurements)
	if !ok {
		t.Fatalf("expected CSRFMeasurements, got %T", result.Measurements)
	}
	if m.NoOrigin.StatusCode == 0 {
		t.Fatal("expected NoOrigin.StatusCode > 0")
	}
	if m.MismatchOrigin.StatusCode == 0 {
		t.Fatal("expected MismatchOrigin.StatusCode > 0")
	}
	if m.Baseline.StatusCode == 0 {
		t.Fatal("expected Baseline.StatusCode > 0")
	}
}

func TestIntegration_IDOR(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ts := newTestServer(t,http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Return resource data regardless of auth (simulates IDOR)
		fmt.Fprint(w, `{"id":"123","name":"private resource"}`)
	}))


	cfg := IDORConfig{
		URL:            ts.URL + "/api/resource/{id}",
		ID:             "123",
		Token:          "attacker-token",
		ExpectedStatus: 403,
		Method:         "GET",
		ProbeConfig:    baseProbeConfig(),
	}

	result, err := VerifyIDOR(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	m, ok := result.Measurements.(IDORMeasurements)
	if !ok {
		t.Fatalf("expected IDORMeasurements, got %T", result.Measurements)
	}
	if m.ProbeRound.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", m.ProbeRound.StatusCode)
	}
	if m.ResourceID != "123" {
		t.Fatalf("expected ResourceID 123, got %s", m.ResourceID)
	}
}

// Suppress unused import warning for json.
var _ = json.Unmarshal
