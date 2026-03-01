package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/srank/ensphere/internal/verify"
)

var (
	fuURL       string
	fuField     string
	fuFilename  string
	fuContent   string
	fuMIMEType  string
	fuVerifyURL string
	fuTechnique string
	fuMethod    string
	fuHeaders   []string
	fuInScope   []string
	fuMaxRisk   int
	fuThrottle  int
	fuTimeout   int
	fuEvidence  string
)

var verifyFileUploadCmd = &cobra.Command{
	Use:   "fileupload",
	Short: "Verify file upload vulnerability",
	Long: `Verify file upload vulnerabilities with extension, MIME, or content-based bypass probes.

Techniques:
  extension_bypass       Upload file with double/bypassed extension (risk 3)
  mime_bypass            Upload file with mismatched MIME type (risk 3)
  content_type_mismatch  Send Content-Type that doesn't match file content (risk 3)
  polyglot_file          Upload polyglot file that is valid in multiple formats (risk 4)
  zip_path_traversal     Upload ZIP with path traversal in filename (risk 4)

Examples:
  ensphere verify fileupload --url "http://target/upload" --filename "shell.php.jpg" --technique extension_bypass --in-scope "*.target.com"
  ensphere verify fileupload --url "http://target/upload" --filename "test.php" --mime-type "image/jpeg" --technique mime_bypass --in-scope "*.target.com"
  ensphere verify fileupload --url "http://target/upload" --filename "poly.php" --content "GIF89a<?php ?>" --technique polyglot_file --in-scope "*.target.com" --max-risk 4
  ensphere verify fileupload --url "http://target/upload" --filename "shell.php" --technique extension_bypass --verify-url "http://target/uploads/shell.php" --in-scope "*.target.com"`,
	RunE: runVerifyFileUpload,
}

func init() {
	verifyFileUploadCmd.Flags().StringVar(&fuURL, "url", "", "Target upload URL (required)")
	verifyFileUploadCmd.Flags().StringVar(&fuField, "field", "file", "Form field name for the file")
	verifyFileUploadCmd.Flags().StringVar(&fuFilename, "filename", "", "Test filename to upload (required)")
	verifyFileUploadCmd.Flags().StringVar(&fuContent, "content", "ensphere_upload_test", "File content to upload")
	verifyFileUploadCmd.Flags().StringVar(&fuMIMEType, "mime-type", "application/octet-stream", "Content-Type for the file part")
	verifyFileUploadCmd.Flags().StringVar(&fuVerifyURL, "verify-url", "", "URL to GET after upload to check accessibility")
	verifyFileUploadCmd.Flags().StringVar(&fuTechnique, "technique", "", "Technique: extension_bypass, mime_bypass, content_type_mismatch, polyglot_file, zip_path_traversal (required)")
	verifyFileUploadCmd.Flags().StringVar(&fuMethod, "method", "POST", "HTTP method")
	verifyFileUploadCmd.Flags().StringSliceVar(&fuHeaders, "header", nil, "Custom headers (key:value, repeatable)")
	verifyFileUploadCmd.Flags().StringSliceVar(&fuInScope, "in-scope", nil, "In-scope patterns (required)")
	verifyFileUploadCmd.Flags().IntVar(&fuMaxRisk, "max-risk", 3, "Maximum risk level (1-5)")
	verifyFileUploadCmd.Flags().IntVar(&fuThrottle, "throttle", 500, "Milliseconds between probes")
	verifyFileUploadCmd.Flags().IntVar(&fuTimeout, "timeout", 10, "HTTP request timeout in seconds")
	verifyFileUploadCmd.Flags().StringVar(&fuEvidence, "evidence", "./evidence.jsonl", "Evidence file path")

	_ = verifyFileUploadCmd.MarkFlagRequired("url")
	_ = verifyFileUploadCmd.MarkFlagRequired("filename")
	_ = verifyFileUploadCmd.MarkFlagRequired("technique")
	_ = verifyFileUploadCmd.MarkFlagRequired("in-scope")

	verifyCmd.AddCommand(verifyFileUploadCmd)
}

func runVerifyFileUpload(cmd *cobra.Command, args []string) error {
	headers := make(map[string]string)
	for _, h := range fuHeaders {
		parts := splitOnce(h, ":")
		if len(parts) == 2 {
			headers[parts[0]] = parts[1]
		}
	}

	cfg := verify.FileUploadConfig{
		URL:       fuURL,
		FieldName: fuField,
		Filename:  fuFilename,
		Content:   fuContent,
		MIMEType:  fuMIMEType,
		VerifyURL: fuVerifyURL,
		Technique: fuTechnique,
		Method:    fuMethod,
		ProbeConfig: verify.ProbeConfig{
			InScope:    fuInScope,
			MaxRisk:    fuMaxRisk,
			ThrottleMs: fuThrottle,
			TimeoutSec: fuTimeout,
			Headers:    headers,
			Evidence:   fuEvidence,
		},
	}

	result, err := verify.VerifyFileUpload(cfg)
	if err != nil {
		var scopeErr *verify.ScopeError
		if errors.As(err, &scopeErr) {
			fmt.Fprintf(os.Stderr, "scope error: %s\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "probe error: %s\n", err)
		os.Exit(3)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "encode error: %s\n", err)
		os.Exit(3)
	}
	return nil
}
