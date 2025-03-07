package history

import (
	"fmt"
	"time"
)

// Statistics 统计信息
type Statistics struct {
	TotalScans       int            `json:"total_scans"`
	TotalFiles       int            `json:"total_files"`
	TotalWebshells   int            `json:"total_webshells"`
	HighRiskCount    int            `json:"high_risk_count"`
	MediumRiskCount  int            `json:"medium_risk_count"`
	LowRiskCount     int            `json:"low_risk_count"`
	FirstScanTime    time.Time      `json:"first_scan_time"`
	LastScanTime     time.Time      `json:"last_scan_time"`
	AverageFileCount float64        `json:"average_file_count"`
	ScansByType      map[string]int `json:"scans_by_type"`
}

// GetStatistics 获取统计信息
func (m *Manager) GetStatistics(startTime, endTime time.Time) (*Statistics, error) {
	stats := &Statistics{
		ScansByType: make(map[string]int),
	}

	// 查询基本统计信息
	row := m.db.QueryRow(`
		SELECT 
			COUNT(*) as total_scans,
			SUM(total_files) as total_files,
			SUM(webshell_count) as total_webshells,
			SUM(high_risk_count) as high_risk_total,
			SUM(medium_risk_count) as medium_risk_total,
			SUM(low_risk_count) as low_risk_total,
			MIN(start_time) as first_scan,
			MAX(end_time) as last_scan,
			AVG(total_files) as avg_files
		FROM scan_history
		WHERE start_time BETWEEN ? AND ?
	`, startTime, endTime)

	err := row.Scan(
		&stats.TotalScans,
		&stats.TotalFiles,
		&stats.TotalWebshells,
		&stats.HighRiskCount,
		&stats.MediumRiskCount,
		&stats.LowRiskCount,
		&stats.FirstScanTime,
		&stats.LastScanTime,
		&stats.AverageFileCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get statistics: %v", err)
	}

	// 查询各类型扫描次数
	rows, err := m.db.Query(`
		SELECT scan_type, COUNT(*) as count
		FROM scan_history
		WHERE start_time BETWEEN ? AND ?
		GROUP BY scan_type
	`, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get scan type statistics: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var scanType string
		var count int
		if err := rows.Scan(&scanType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}
		stats.ScansByType[scanType] = count
	}

	return stats, nil
}

// startCleanupTask 启动清理任务
func (m *Manager) startCleanupTask() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := m.cleanup(); err != nil {
			fmt.Printf("History cleanup failed: %v\n", err)
		}
	}
}

// cleanup 清理过期记录
func (m *Manager) cleanup() error {
	// 清理过期记录
	cutoff := time.Now().AddDate(0, 0, -m.retentionDays)
	_, err := m.db.Exec("DELETE FROM scan_history WHERE start_time < ?", cutoff)
	if err != nil {
		return fmt.Errorf("failed to delete old records: %v", err)
	}

	// 如果记录数超过限制，删除最旧的记录
	if m.maxRecords > 0 {
		_, err = m.db.Exec(`
			DELETE FROM scan_history
			WHERE id IN (
				SELECT id FROM scan_history
				ORDER BY start_time DESC
				LIMIT -1 OFFSET ?
			)
		`, m.maxRecords)
		if err != nil {
			return fmt.Errorf("failed to limit record count: %v", err)
		}
	}

	return nil
}

// Close 关闭历史记录管理器
func (m *Manager) Close() error {
	return m.db.Close()
}
