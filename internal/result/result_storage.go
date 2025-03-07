package result

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"webshell-detector/internal/detector"

	_ "github.com/mattn/go-sqlite3"
)

// Storage 结果存储器
type Storage struct {
	db *sql.DB
}

// NewStorage 创建结果存储器
func NewStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	if err := initResultDatabase(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	return &Storage{db: db}, nil
}

// initResultDatabase 初始化结果数据库
func initResultDatabase(db *sql.DB) error {
	createTable := `
	CREATE TABLE IF NOT EXISTS scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_path TEXT NOT NULL,
		is_webshell BOOLEAN NOT NULL,
		risk_level TEXT NOT NULL,
		total_score REAL NOT NULL,
		feature_score REAL,
		behavior_score REAL,
		ml_score REAL,
		matched_features TEXT,
		behaviors TEXT,
		scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
		scan_duration INTEGER,
		scan_type TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_file_path ON scan_results(file_path);
	CREATE INDEX IF NOT EXISTS idx_scan_time ON scan_results(scan_time);
	CREATE INDEX IF NOT EXISTS idx_risk_level ON scan_results(risk_level);
	`

	_, err := db.Exec(createTable)
	return err
}

// StoreResult 存储检测结果
func (s *Storage) StoreResult(result *detector.DetectionResult, scanType string, duration time.Duration) error {
	// 将特征和行为列表转换为JSON
	matchedFeatures, err := json.Marshal(result.MatchedFeatures)
	if err != nil {
		return fmt.Errorf("failed to marshal matched features: %v", err)
	}

	behaviors, err := json.Marshal(result.Behaviors)
	if err != nil {
		return fmt.Errorf("failed to marshal behaviors: %v", err)
	}

	// 插入结果
	_, err = s.db.Exec(`
		INSERT INTO scan_results (
			file_path, is_webshell, risk_level, total_score,
			feature_score, behavior_score, ml_score,
			matched_features, behaviors, scan_duration, scan_type
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		result.FilePath,
		result.IsWebshell,
		result.RiskLevel,
		result.TotalScore,
		result.FeatureScore,
		result.BehaviorScore,
		result.MLScore,
		string(matchedFeatures),
		string(behaviors),
		duration.Milliseconds(),
		scanType,
	)

	if err != nil {
		return fmt.Errorf("failed to store result: %v", err)
	}

	return nil
}

// QueryResults 查询检测结果
func (s *Storage) QueryResults(query ResultQuery) ([]*detector.DetectionResult, error) {
	// 构建查询SQL
	sql := `
		SELECT file_path, is_webshell, risk_level, total_score,
		       feature_score, behavior_score, ml_score,
		       matched_features, behaviors, scan_time
		FROM scan_results
		WHERE 1=1
	`
	var args []interface{}

	if query.StartTime != nil {
		sql += " AND scan_time >= ?"
		args = append(args, query.StartTime)
	}
	if query.EndTime != nil {
		sql += " AND scan_time <= ?"
		args = append(args, query.EndTime)
	}
	if query.RiskLevel != "" {
		sql += " AND risk_level = ?"
		args = append(args, query.RiskLevel)
	}
	if query.IsWebshell != nil {
		sql += " AND is_webshell = ?"
		args = append(args, *query.IsWebshell)
	}

	sql += " ORDER BY scan_time DESC"
	if query.Limit > 0 {
		sql += " LIMIT ?"
		args = append(args, query.Limit)
	}

	// 执行查询
	rows, err := s.db.Query(sql, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query results: %v", err)
	}
	defer rows.Close()

	var results []*detector.DetectionResult
	for rows.Next() {
		var result detector.DetectionResult
		var matchedFeaturesJSON, behaviorsJSON string
		var scanTime time.Time

		err := rows.Scan(
			&result.FilePath,
			&result.IsWebshell,
			&result.RiskLevel,
			&result.TotalScore,
			&result.FeatureScore,
			&result.BehaviorScore,
			&result.MLScore,
			&matchedFeaturesJSON,
			&behaviorsJSON,
			&scanTime,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %v", err)
		}

		// 解析JSON字段
		if err := json.Unmarshal([]byte(matchedFeaturesJSON), &result.MatchedFeatures); err != nil {
			return nil, fmt.Errorf("failed to unmarshal matched features: %v", err)
		}
		if err := json.Unmarshal([]byte(behaviorsJSON), &result.Behaviors); err != nil {
			return nil, fmt.Errorf("failed to unmarshal behaviors: %v", err)
		}

		results = append(results, &result)
	}

	return results, nil
}

// ResultQuery 结果查询条件
type ResultQuery struct {
	StartTime  *time.Time
	EndTime    *time.Time
	RiskLevel  string
	IsWebshell *bool
	Limit      int
}

// GetStatistics 获取统计信息
func (s *Storage) GetStatistics(startTime, endTime time.Time) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 查询总体统计
	row := s.db.QueryRow(`
		SELECT 
			COUNT(*) as total,
			SUM(CASE WHEN is_webshell = 1 THEN 1 ELSE 0 END) as webshells,
			AVG(total_score) as avg_score,
			SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_risk,
			SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_risk,
			SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_risk
		FROM scan_results
		WHERE scan_time BETWEEN ? AND ?
	`, startTime, endTime)

	var total, webshells, highRisk, mediumRisk, lowRisk int
	var avgScore float64
	err := row.Scan(&total, &webshells, &avgScore, &highRisk, &mediumRisk, &lowRisk)
	if err != nil {
		return nil, fmt.Errorf("failed to get statistics: %v", err)
	}

	stats["total_scans"] = total
	stats["total_webshells"] = webshells
	stats["average_score"] = avgScore
	stats["risk_levels"] = map[string]int{
		"high":   highRisk,
		"medium": mediumRisk,
		"low":    lowRisk,
	}

	return stats, nil
}

// Close 关闭存储器
func (s *Storage) Close() error {
	return s.db.Close()
}
