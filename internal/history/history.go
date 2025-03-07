package history

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Manager 历史记录管理器
type Manager struct {
	db              *sql.DB
	retentionDays   int
	maxRecords      int
	cleanupInterval time.Duration
}

// Config 历史记录配置
type Config struct {
	DBPath          string
	RetentionDays   int
	MaxRecords      int
	CleanupInterval time.Duration
}

// NewManager 创建历史记录管理器
func NewManager(cfg Config) (*Manager, error) {
	db, err := sql.Open("sqlite3", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	manager := &Manager{
		db:              db,
		retentionDays:   cfg.RetentionDays,
		maxRecords:      cfg.MaxRecords,
		cleanupInterval: cfg.CleanupInterval,
	}

	if err := manager.initDatabase(); err != nil {
		db.Close()
		return nil, err
	}

	// 启动定期清理任务
	go manager.startCleanupTask()

	return manager, nil
}

// initDatabase 初始化数据库
func (m *Manager) initDatabase() error {
	createTable := `
	CREATE TABLE IF NOT EXISTS scan_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id TEXT NOT NULL,
		scan_type TEXT NOT NULL,
		start_time DATETIME NOT NULL,
		end_time DATETIME NOT NULL,
		total_files INTEGER NOT NULL,
		webshell_count INTEGER NOT NULL,
		high_risk_count INTEGER NOT NULL,
		medium_risk_count INTEGER NOT NULL,
		low_risk_count INTEGER NOT NULL,
		scan_config TEXT,
		scan_results TEXT,
		error_message TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_history(start_time);
	CREATE INDEX IF NOT EXISTS idx_scan_type ON scan_history(scan_type);
	`

	_, err := m.db.Exec(createTable)
	return err
}

// RecordScan 记录扫描历史
func (m *Manager) RecordScan(record *ScanRecord) error {
	scanConfig, err := json.Marshal(record.ScanConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal scan config: %v", err)
	}

	scanResults, err := json.Marshal(record.ScanResults)
	if err != nil {
		return fmt.Errorf("failed to marshal scan results: %v", err)
	}

	_, err = m.db.Exec(`
		INSERT INTO scan_history (
			scan_id, scan_type, start_time, end_time,
			total_files, webshell_count, high_risk_count,
			medium_risk_count, low_risk_count,
			scan_config, scan_results, error_message
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.ScanID,
		record.ScanType,
		record.StartTime,
		record.EndTime,
		record.TotalFiles,
		record.WebshellCount,
		record.HighRiskCount,
		record.MediumRiskCount,
		record.LowRiskCount,
		scanConfig,
		scanResults,
		record.ErrorMessage,
	)

	return err
}
