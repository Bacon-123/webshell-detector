package history

import (
	"encoding/json"
	"fmt"
	"time"

	"webshell-detector/internal/detector"
)

// ScanRecord 扫描记录
type ScanRecord struct {
	ScanID          string                      `json:"scan_id"`
	ScanType        string                      `json:"scan_type"`
	StartTime       time.Time                   `json:"start_time"`
	EndTime         time.Time                   `json:"end_time"`
	TotalFiles      int                         `json:"total_files"`
	WebshellCount   int                         `json:"webshell_count"`
	HighRiskCount   int                         `json:"high_risk_count"`
	MediumRiskCount int                         `json:"medium_risk_count"`
	LowRiskCount    int                         `json:"low_risk_count"`
	ScanConfig      map[string]interface{}      `json:"scan_config"`
	ScanResults     []*detector.DetectionResult `json:"scan_results"`
	ErrorMessage    string                      `json:"error_message"`
}

// QueryOptions 查询选项
type QueryOptions struct {
	StartTime *time.Time
	EndTime   *time.Time
	ScanType  string
	ScanID    string
	Limit     int
	Offset    int
	SortBy    string
	SortOrder string
}

// QueryHistory 查询历史记录
func (m *Manager) QueryHistory(opts QueryOptions) ([]*ScanRecord, error) {
	query := `
		SELECT scan_id, scan_type, start_time, end_time,
		       total_files, webshell_count, high_risk_count,
		       medium_risk_count, low_risk_count,
		       scan_config, scan_results, error_message
		FROM scan_history
		WHERE 1=1
	`
	var args []interface{}

	if opts.StartTime != nil {
		query += " AND start_time >= ?"
		args = append(args, opts.StartTime)
	}
	if opts.EndTime != nil {
		query += " AND end_time <= ?"
		args = append(args, opts.EndTime)
	}
	if opts.ScanType != "" {
		query += " AND scan_type = ?"
		args = append(args, opts.ScanType)
	}
	if opts.ScanID != "" {
		query += " AND scan_id = ?"
		args = append(args, opts.ScanID)
	}

	// 添加排序
	if opts.SortBy != "" {
		query += fmt.Sprintf(" ORDER BY %s", opts.SortBy)
		if opts.SortOrder != "" {
			query += " " + opts.SortOrder
		}
	} else {
		query += " ORDER BY start_time DESC"
	}

	// 添加分页
	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
		if opts.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, opts.Offset)
		}
	}

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query history: %v", err)
	}
	defer rows.Close()

	var records []*ScanRecord
	for rows.Next() {
		var record ScanRecord
		var scanConfig, scanResults string

		err := rows.Scan(
			&record.ScanID,
			&record.ScanType,
			&record.StartTime,
			&record.EndTime,
			&record.TotalFiles,
			&record.WebshellCount,
			&record.HighRiskCount,
			&record.MediumRiskCount,
			&record.LowRiskCount,
			&scanConfig,
			&scanResults,
			&record.ErrorMessage,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}

		// 解析JSON字段
		if err := json.Unmarshal([]byte(scanConfig), &record.ScanConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scan config: %v", err)
		}
		if err := json.Unmarshal([]byte(scanResults), &record.ScanResults); err != nil {
			return nil, fmt.Errorf("failed to unmarshal scan results: %v", err)
		}

		records = append(records, &record)
	}

	return records, nil
}
