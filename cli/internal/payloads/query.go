package payloads

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// QueryPayloads filters payloads and returns ranked results with tags.
func QueryPayloads(db *sql.DB, f PayloadFilter) (*QueryOutput, error) {
	var (
		where     []string
		whereArgs []any
		rankCols  []rankCol
	)

	// Required filter: vuln_type (always exact match)
	where = append(where, "p.vuln_type = ?")
	whereArgs = append(whereArgs, f.VulnType)

	// Optional nullable filters: broadening semantics
	// When set: match exact value OR NULL (engine-agnostic payloads always included)
	// When unset: match everything
	addNullableFilter(&where, &whereArgs, &rankCols, "p.db_engine", f.DBEngine)
	addNullableFilter(&where, &whereArgs, &rankCols, "p.runtime", f.Runtime)

	// Optional exact filters (non-nullable columns)
	addExactFilter(&where, &whereArgs, "p.technique", f.Technique)
	addExactFilter(&where, &whereArgs, "p.injection_surface", f.Surface)
	addNullableFilter(&where, &whereArgs, &rankCols, "p.content_type", f.ContentType)
	addExactFilter(&where, &whereArgs, "p.encoding", f.Encoding)
	addNullableFilter(&where, &whereArgs, &rankCols, "p.string_boundary", f.Boundary)

	// Max risk filter
	if f.MaxRisk > 0 {
		where = append(where, "p.risk <= ?")
		whereArgs = append(whereArgs, f.MaxRisk)
	}

	// Tag filter via subquery
	if f.Tag != "" {
		where = append(where, "EXISTS (SELECT 1 FROM payload_tags t WHERE t.payload_id = p.id AND t.tag = ?)")
		whereArgs = append(whereArgs, f.Tag)
	}

	// Build rank expression: exact matches score 0, NULL fallback scores 1
	// Use (0+0) instead of bare 0 to prevent SQLite interpreting it as a column index
	rankSQL := "(0+0)"
	var rankArgs []any
	if len(rankCols) > 0 {
		parts := make([]string, len(rankCols))
		for i, rc := range rankCols {
			parts[i] = fmt.Sprintf("CASE WHEN %s = ? THEN 0 ELSE 1 END", rc.column)
			rankArgs = append(rankArgs, rc.value)
		}
		rankSQL = "(" + strings.Join(parts, " + ") + ")"
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}

	// Assemble args: WHERE args, then rank args, then LIMIT
	allArgs := make([]any, 0, len(whereArgs)+len(rankArgs)+1)
	allArgs = append(allArgs, whereArgs...)
	allArgs = append(allArgs, rankArgs...)
	allArgs = append(allArgs, limit)

	query := fmt.Sprintf(`
		SELECT p.id, p.vuln_type, p.db_engine, p.runtime, p.technique,
		       p.injection_surface, p.content_type, p.encoding, p.string_boundary,
		       p.evidence_type, p.risk, p.payload, p.placeholders, p.notes, p.source
		FROM payloads p
		WHERE %s
		ORDER BY %s ASC, p.risk ASC, p.id ASC
		LIMIT ?
	`, strings.Join(where, " AND "), rankSQL)

	rows, err := db.Query(query, allArgs...)
	if err != nil {
		return nil, fmt.Errorf("query payloads: %w", err)
	}
	defer rows.Close()

	results := make([]PayloadResult, 0)
	var ids []string

	for rows.Next() {
		var (
			r                PayloadResult
			dbEngine         sql.NullString
			runtime          sql.NullString
			contentType      sql.NullString
			stringBoundary   sql.NullString
			placeholdersJSON string
			vulnType         string
		)
		err := rows.Scan(
			&r.ID, &vulnType, &dbEngine, &runtime, &r.Technique,
			&r.InjectionSurface, &contentType, &r.Encoding, &stringBoundary,
			&r.EvidenceType, &r.Risk, &r.Payload, &placeholdersJSON, &r.Notes, &r.Source,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		if stringBoundary.Valid {
			r.StringBoundary = &stringBoundary.String
		}

		var placeholders []string
		if err := json.Unmarshal([]byte(placeholdersJSON), &placeholders); err != nil {
			placeholders = []string{}
		}
		r.Placeholders = placeholders
		r.Tags = []string{}

		results = append(results, r)
		ids = append(ids, r.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	// Batch load tags
	if len(ids) > 0 {
		tagMap, err := loadTags(db, ids)
		if err != nil {
			return nil, err
		}
		for i := range results {
			if tags, ok := tagMap[results[i].ID]; ok {
				results[i].Tags = tags
			}
		}
	}

	// Build echoed query
	echoedQuery := map[string]any{
		"vuln_type": f.VulnType,
	}
	if f.DBEngine != "" {
		echoedQuery["db_engine"] = f.DBEngine
	}
	if f.Runtime != "" {
		echoedQuery["runtime"] = f.Runtime
	}
	if f.Technique != "" {
		echoedQuery["technique"] = f.Technique
	}
	if f.Surface != "" {
		echoedQuery["injection_surface"] = f.Surface
	}
	if f.ContentType != "" {
		echoedQuery["content_type"] = f.ContentType
	}
	if f.Encoding != "" {
		echoedQuery["encoding"] = f.Encoding
	}
	if f.Boundary != "" {
		echoedQuery["string_boundary"] = f.Boundary
	}
	if f.Tag != "" {
		echoedQuery["tag"] = f.Tag
	}
	if f.MaxRisk > 0 {
		echoedQuery["max_risk"] = f.MaxRisk
	}
	echoedQuery["limit"] = limit

	return &QueryOutput{
		Query:   echoedQuery,
		Count:   len(results),
		Results: results,
	}, nil
}

type rankCol struct {
	column string
	value  string
}

// addNullableFilter: column = value OR column IS NULL.
func addNullableFilter(where *[]string, args *[]any, ranks *[]rankCol, column, value string) {
	if value == "" {
		return
	}
	*where = append(*where, fmt.Sprintf("(%s = ? OR %s IS NULL)", column, column))
	*args = append(*args, value)
	*ranks = append(*ranks, rankCol{column: column, value: value})
}

// addExactFilter: exact match only (non-nullable column).
func addExactFilter(where *[]string, args *[]any, column, value string) {
	if value == "" {
		return
	}
	*where = append(*where, fmt.Sprintf("%s = ?", column))
	*args = append(*args, value)
}

// loadTags batch-loads tags for a set of payload IDs.
func loadTags(db *sql.DB, ids []string) (map[string][]string, error) {
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}

	query := fmt.Sprintf(
		"SELECT payload_id, tag FROM payload_tags WHERE payload_id IN (%s) ORDER BY payload_id, tag",
		strings.Join(placeholders, ","),
	)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("load tags: %w", err)
	}
	defer rows.Close()

	tagMap := make(map[string][]string)
	for rows.Next() {
		var payloadID, tag string
		if err := rows.Scan(&payloadID, &tag); err != nil {
			return nil, fmt.Errorf("scan tag: %w", err)
		}
		tagMap[payloadID] = append(tagMap[payloadID], tag)
	}
	return tagMap, rows.Err()
}
