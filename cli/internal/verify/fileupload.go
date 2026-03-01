package verify

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"

	"github.com/srank/ensphere/internal/evidence"
)

// FileUploadConfig holds configuration for file upload vulnerability verification.
type FileUploadConfig struct {
	URL       string
	FieldName string // form field name (default: "file")
	Filename  string // test filename (e.g., "shell.php.jpg")
	Content   string // file content (default: "ensphere_upload_test")
	MIMEType  string // Content-Type for the file part
	VerifyURL string // optional: GET this URL after upload to check accessibility
	Technique string
	Method    string // default: POST
	ProbeConfig
}

// fileUploadTechniqueRisk maps each file upload technique to its risk level.
var fileUploadTechniqueRisk = map[string]int{
	"extension_bypass":      3,
	"mime_bypass":           3,
	"content_type_mismatch": 3,
	"polyglot_file":         4,
	"zip_path_traversal":    4,
}

// MultipartHTTPProbe sends a multipart file upload request and captures timing + response hash.
func MultipartHTTPProbe(method, url, fieldName, filename, content, mimeType string,
	headers map[string]string, timeoutSec int) ProbeResponse {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, fieldName, filename))
	h.Set("Content-Type", mimeType)
	part, err := writer.CreatePart(h)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("create part: %w", err)}
	}
	part.Write([]byte(content))
	writer.Close()

	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		return ProbeResponse{Error: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()

	if err != nil {
		return ProbeResponse{ElapsedMs: elapsed, Error: fmt.Errorf("request failed: %w", err)}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ProbeResponse{
			StatusCode: resp.StatusCode,
			ElapsedMs:  elapsed,
			Headers:    resp.Header,
			Error:      fmt.Errorf("read body: %w", err),
		}
	}

	bodyStr := string(respBody)
	hash := fmt.Sprintf("%x", sha256.Sum256(respBody))

	return ProbeResponse{
		StatusCode: resp.StatusCode,
		Body:       bodyStr,
		BodyHash:   hash,
		ElapsedMs:  elapsed,
		Headers:    resp.Header,
	}
}

// VerifyFileUpload runs the file upload vulnerability verification probe.
func VerifyFileUpload(cfg FileUploadConfig) (*ProbeResult, error) {
	if err := CheckScope(cfg.URL, cfg.InScope); err != nil {
		return nil, err
	}

	risk, ok := fileUploadTechniqueRisk[cfg.Technique]
	if !ok {
		return nil, &ScopeError{Msg: fmt.Sprintf("unsupported technique %q — use: extension_bypass, mime_bypass, content_type_mismatch, polyglot_file, zip_path_traversal", cfg.Technique)}
	}

	if err := CheckMaxRisk(risk, cfg.MaxRisk); err != nil {
		return nil, err
	}

	timer := NewTimer()
	throttle := NewThrottle(cfg.ThrottleMs)

	var ew *evidence.Writer
	if cfg.Evidence != "" {
		var err error
		ew, err = evidence.NewWriter(cfg.Evidence)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open evidence file: %v\n", err)
		} else {
			defer ew.Close()
		}
	}

	return verifyFileUploadProbe(cfg, throttle, timer, ew)
}

func verifyFileUploadProbe(cfg FileUploadConfig, throttle *Throttle, timer *Timer, ew *evidence.Writer) (*ProbeResult, error) {
	probeCount := 0

	// Upload probe
	throttle.Wait()
	probeCount++
	uploadResp := MultipartHTTPProbe(cfg.Method, cfg.URL, cfg.FieldName, cfg.Filename, cfg.Content, cfg.MIMEType, cfg.Headers, cfg.TimeoutSec)
	if uploadResp.Error != nil {
		return nil, fmt.Errorf("upload probe: %w", uploadResp.Error)
	}
	fmt.Fprintf(os.Stderr, "[UPLOAD] status=%d hash=%s\n", uploadResp.StatusCode, uploadResp.BodyHash[:16])
	writeEvidence(ew, "file_upload", cfg.Technique, cfg.URL, cfg.FieldName, uploadResp.StatusCode,
		fmt.Sprintf("%dms", uploadResp.ElapsedMs), "probe", fmt.Sprintf("filename=%s mime=%s", cfg.Filename, cfg.MIMEType))

	filenameInResponse := strings.Contains(uploadResp.Body, cfg.Filename)
	uploadAccepted := uploadResp.StatusCode >= 200 && uploadResp.StatusCode < 300

	uploadRound := RoundResult{
		StatusCode: uploadResp.StatusCode,
		ElapsedMs:  uploadResp.ElapsedMs,
		BodyHash:   uploadResp.BodyHash,
		BodyLength: len(uploadResp.Body),
	}

	snippet := uploadResp.Body
	if len(snippet) > 500 {
		snippet = snippet[:500]
	}

	var verifyRound *RoundResult
	var verifyAccessible *bool

	// If VerifyURL provided, check if uploaded file is accessible
	if cfg.VerifyURL != "" {
		throttle.Wait()
		probeCount++
		verifyResp := HTTPProbe("GET", cfg.VerifyURL, "", cfg.Headers, cfg.TimeoutSec)
		if verifyResp.Error != nil {
			fmt.Fprintf(os.Stderr, "[VERIFY] error: %v\n", verifyResp.Error)
		} else {
			fmt.Fprintf(os.Stderr, "[VERIFY] status=%d hash=%s\n", verifyResp.StatusCode, verifyResp.BodyHash[:16])
			writeEvidence(ew, "file_upload", cfg.Technique, cfg.VerifyURL, cfg.FieldName, verifyResp.StatusCode,
				fmt.Sprintf("%dms", verifyResp.ElapsedMs), "verify", fmt.Sprintf("verify URL check status=%d", verifyResp.StatusCode))
			vr := RoundResult{
				StatusCode: verifyResp.StatusCode,
				ElapsedMs:  verifyResp.ElapsedMs,
				BodyHash:   verifyResp.BodyHash,
				BodyLength: len(verifyResp.Body),
			}
			verifyRound = &vr
			accessible := verifyResp.StatusCode == 200
			verifyAccessible = &accessible
		}
	}

	return &ProbeResult{
		SchemaVersion: 2,
		VulnType:      "file_upload",
		Technique:     cfg.Technique,
		StartedAt:     timer.StartedAt(),
		ProbeCount:    probeCount,
		Duration:      timer.Elapsed(),
		Measurements: FileUploadMeasurements{
			Technique:          cfg.Technique,
			UploadProbe:        uploadRound,
			FilenameInResponse: filenameInResponse,
			UploadAccepted:     uploadAccepted,
			VerifyProbe:        verifyRound,
			VerifyAccessible:   verifyAccessible,
			FilenameSent:       cfg.Filename,
			MIMETypeSent:       cfg.MIMEType,
			ContentSent:        cfg.Content,
			ResponseSnippet:    snippet,
		},
	}, nil
}
