package openapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Test API", "version": "1.0.0", "description": "A test API"},
  "servers": [{"url": "https://api.example.com", "description": "Production"}],
  "security": [{"bearerAuth": []}],
  "paths": {
    "/users": {
      "get": {
        "operationId": "listUsers",
        "summary": "List all users",
        "tags": ["users"],
        "parameters": [
          {"name": "limit", "in": "query", "required": false, "schema": {"type": "integer"}}
        ]
      },
      "post": {
        "operationId": "createUser",
        "summary": "Create a user",
        "tags": ["users"],
        "requestBody": {"required": true, "content": {"application/json": {}}}
      }
    },
    "/users/{id}": {
      "get": {
        "operationId": "getUser",
        "parameters": [
          {"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}
        ],
        "security": []
      },
      "delete": {
        "deprecated": true,
        "operationId": "deleteUser"
      }
    }
  },
  "components": {
    "securitySchemes": {
      "bearerAuth": {"type": "http", "scheme": "bearer"}
    }
  }
}`

func TestParseSpec_BasicInfo(t *testing.T) {
	spec, err := parseSpec([]byte(testSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}
	if spec.Title != "Test API" {
		t.Errorf("title = %q, want %q", spec.Title, "Test API")
	}
	if spec.Version != "1.0.0" {
		t.Errorf("version = %q, want %q", spec.Version, "1.0.0")
	}
	if spec.Description != "A test API" {
		t.Errorf("description = %q, want %q", spec.Description, "A test API")
	}
}

func TestParseSpec_Servers(t *testing.T) {
	spec, err := parseSpec([]byte(testSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}
	if len(spec.Servers) != 1 {
		t.Fatalf("servers count = %d, want 1", len(spec.Servers))
	}
	if spec.Servers[0].URL != "https://api.example.com" {
		t.Errorf("server url = %q, want %q", spec.Servers[0].URL, "https://api.example.com")
	}
	if spec.Servers[0].Description != "Production" {
		t.Errorf("server description = %q, want %q", spec.Servers[0].Description, "Production")
	}
}

func TestParseSpec_Endpoints(t *testing.T) {
	spec, err := parseSpec([]byte(testSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}
	if spec.TotalPaths != 2 {
		t.Errorf("total_paths = %d, want 2", spec.TotalPaths)
	}
	if spec.TotalOps != 4 {
		t.Errorf("total_operations = %d, want 4", spec.TotalOps)
	}
	if len(spec.Endpoints) != 4 {
		t.Fatalf("endpoints count = %d, want 4", len(spec.Endpoints))
	}

	// Endpoints are sorted by path then method.
	// /users DELETE(no), GET, POST; /users/{id} DELETE, GET
	expected := []struct {
		method string
		path   string
	}{
		{"GET", "/users"},
		{"POST", "/users"},
		{"DELETE", "/users/{id}"},
		{"GET", "/users/{id}"},
	}
	for i, e := range expected {
		if spec.Endpoints[i].Method != e.method || spec.Endpoints[i].Path != e.path {
			t.Errorf("endpoint[%d] = %s %s, want %s %s",
				i, spec.Endpoints[i].Method, spec.Endpoints[i].Path, e.method, e.path)
		}
	}
}

func TestParseSpec_Parameters(t *testing.T) {
	spec, err := parseSpec([]byte(testSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}

	// GET /users has a "limit" query parameter.
	var getUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "GET" && spec.Endpoints[i].Path == "/users" {
			getUsers = &spec.Endpoints[i]
			break
		}
	}
	if getUsers == nil {
		t.Fatal("GET /users endpoint not found")
	}
	if len(getUsers.Parameters) != 1 {
		t.Fatalf("GET /users params count = %d, want 1", len(getUsers.Parameters))
	}
	p := getUsers.Parameters[0]
	if p.Name != "limit" {
		t.Errorf("param name = %q, want %q", p.Name, "limit")
	}
	if p.In != "query" {
		t.Errorf("param in = %q, want %q", p.In, "query")
	}
	if p.Required {
		t.Error("param required = true, want false")
	}
	if p.Type != "integer" {
		t.Errorf("param type = %q, want %q", p.Type, "integer")
	}

	// GET /users/{id} has an "id" path parameter.
	var getUserByID *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "GET" && spec.Endpoints[i].Path == "/users/{id}" {
			getUserByID = &spec.Endpoints[i]
			break
		}
	}
	if getUserByID == nil {
		t.Fatal("GET /users/{id} endpoint not found")
	}
	if len(getUserByID.Parameters) != 1 {
		t.Fatalf("GET /users/{id} params count = %d, want 1", len(getUserByID.Parameters))
	}
	pid := getUserByID.Parameters[0]
	if pid.Name != "id" || pid.In != "path" || !pid.Required || pid.Type != "string" {
		t.Errorf("GET /users/{id} param = %+v, want name=id in=path required=true type=string", pid)
	}
}

func TestParseSpec_RequestBody(t *testing.T) {
	spec, err := parseSpec([]byte(testSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}

	// POST /users has a request body.
	var postUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "POST" && spec.Endpoints[i].Path == "/users" {
			postUsers = &spec.Endpoints[i]
			break
		}
	}
	if postUsers == nil {
		t.Fatal("POST /users endpoint not found")
	}
	if postUsers.RequestBody == nil {
		t.Fatal("POST /users request_body is nil")
	}
	if !postUsers.RequestBody.Required {
		t.Error("POST /users request_body.required = false, want true")
	}
	if len(postUsers.RequestBody.ContentTypes) != 1 || postUsers.RequestBody.ContentTypes[0] != "application/json" {
		t.Errorf("POST /users content_types = %v, want [application/json]", postUsers.RequestBody.ContentTypes)
	}

	// GET /users should have no request body.
	var getUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "GET" && spec.Endpoints[i].Path == "/users" {
			getUsers = &spec.Endpoints[i]
			break
		}
	}
	if getUsers == nil {
		t.Fatal("GET /users endpoint not found")
	}
	if getUsers.RequestBody != nil {
		t.Error("GET /users request_body should be nil")
	}
}

func TestParseSpec_AuthRequired(t *testing.T) {
	spec, err := parseSpec([]byte(testSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}

	// GET /users inherits top-level security -> auth required.
	// GET /users/{id} has "security": [] -> auth NOT required.
	// DELETE /users/{id} inherits top-level security -> auth required.
	for _, ep := range spec.Endpoints {
		switch {
		case ep.Method == "GET" && ep.Path == "/users/{id}":
			if ep.AuthRequired {
				t.Errorf("GET /users/{id} auth_required = true, want false (empty security override)")
			}
		case ep.Method == "GET" && ep.Path == "/users":
			if !ep.AuthRequired {
				t.Errorf("GET /users auth_required = false, want true (inherits top-level)")
			}
		case ep.Method == "POST" && ep.Path == "/users":
			if !ep.AuthRequired {
				t.Errorf("POST /users auth_required = false, want true (inherits top-level)")
			}
		case ep.Method == "DELETE" && ep.Path == "/users/{id}":
			if !ep.AuthRequired {
				t.Errorf("DELETE /users/{id} auth_required = false, want true (inherits top-level)")
			}
		}
	}
}

func TestParseSpec_Deprecated(t *testing.T) {
	spec, err := parseSpec([]byte(testSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}

	// DELETE /users/{id} is deprecated.
	var deleteUser *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "DELETE" && spec.Endpoints[i].Path == "/users/{id}" {
			deleteUser = &spec.Endpoints[i]
			break
		}
	}
	if deleteUser == nil {
		t.Fatal("DELETE /users/{id} endpoint not found")
	}
	if !deleteUser.Deprecated {
		t.Error("DELETE /users/{id} deprecated = false, want true")
	}

	// GET /users should not be deprecated.
	var getUsers *Endpoint
	for i := range spec.Endpoints {
		if spec.Endpoints[i].Method == "GET" && spec.Endpoints[i].Path == "/users" {
			getUsers = &spec.Endpoints[i]
			break
		}
	}
	if getUsers == nil {
		t.Fatal("GET /users endpoint not found")
	}
	if getUsers.Deprecated {
		t.Error("GET /users deprecated = true, want false")
	}
}

func TestParseSpec_EmptyPaths(t *testing.T) {
	data := `{"openapi":"3.0.0","info":{"title":"Empty","version":"0.1.0"},"paths":{}}`
	spec, err := parseSpec([]byte(data))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}
	if spec.TotalPaths != 0 {
		t.Errorf("total_paths = %d, want 0", spec.TotalPaths)
	}
	if spec.TotalOps != 0 {
		t.Errorf("total_operations = %d, want 0", spec.TotalOps)
	}
	if len(spec.Endpoints) != 0 {
		t.Errorf("endpoints count = %d, want 0", len(spec.Endpoints))
	}
}

func TestParseSpec_YAML(t *testing.T) {
	yamlSpec := `
openapi: "3.0.0"
info:
  title: YAML API
  version: "2.0.0"
  description: A YAML spec
servers:
  - url: https://yaml.example.com
paths:
  /health:
    get:
      operationId: healthCheck
      summary: Health check
      parameters:
        - name: verbose
          in: query
          required: false
          schema:
            type: boolean
`
	spec, err := parseSpec([]byte(yamlSpec))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}
	if spec.Title != "YAML API" {
		t.Errorf("title = %q, want %q", spec.Title, "YAML API")
	}
	if spec.Version != "2.0.0" {
		t.Errorf("version = %q, want %q", spec.Version, "2.0.0")
	}
	if spec.TotalPaths != 1 {
		t.Errorf("total_paths = %d, want 1", spec.TotalPaths)
	}
	if spec.TotalOps != 1 {
		t.Errorf("total_operations = %d, want 1", spec.TotalOps)
	}
	if len(spec.Endpoints) != 1 {
		t.Fatalf("endpoints count = %d, want 1", len(spec.Endpoints))
	}
	ep := spec.Endpoints[0]
	if ep.Method != "GET" || ep.Path != "/health" {
		t.Errorf("endpoint = %s %s, want GET /health", ep.Method, ep.Path)
	}
	if ep.OperationID != "healthCheck" {
		t.Errorf("operationId = %q, want %q", ep.OperationID, "healthCheck")
	}
	if len(ep.Parameters) != 1 || ep.Parameters[0].Name != "verbose" {
		t.Errorf("parameters = %+v, want [{Name:verbose In:query ...}]", ep.Parameters)
	}
	// No top-level security -> auth not required.
	if ep.AuthRequired {
		t.Error("auth_required = true, want false (no top-level security)")
	}
}

func TestParseSpec_MissingInfo(t *testing.T) {
	data := `{"openapi":"3.0.0","paths":{"/ping":{"get":{"operationId":"ping"}}}}`
	spec, err := parseSpec([]byte(data))
	if err != nil {
		t.Fatalf("parseSpec error: %v", err)
	}
	if spec.Title != "" {
		t.Errorf("title = %q, want empty", spec.Title)
	}
	if spec.Version != "" {
		t.Errorf("version = %q, want empty", spec.Version)
	}
	if spec.TotalPaths != 1 {
		t.Errorf("total_paths = %d, want 1", spec.TotalPaths)
	}
	if spec.TotalOps != 1 {
		t.Errorf("total_operations = %d, want 1", spec.TotalOps)
	}
}

func TestParseSpec_InvalidData(t *testing.T) {
	_, err := parseSpec([]byte("<<<not valid>>>"))
	if err == nil {
		t.Error("expected error for invalid data, got nil")
	}
}

func TestParseURL_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, "<html>Not Found</html>")
	}))
	defer srv.Close()

	_, err := ParseURL(srv.URL, 5)
	if err == nil {
		t.Fatal("expected error for 404 response")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404, got: %s", err)
	}
}
