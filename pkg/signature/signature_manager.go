package signature

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Signature 特征结构
type Signature struct {
	ID          int     `json:"id"`
	Pattern     string  `json:"pattern"`     // 特征模式
	Type        string  `json:"type"`        // 特征类型：regex/string/function
	Description string  `json:"description"` // 特征描述
	Weight      float64 `json:"weight"`      // 特征权重
	Category    string  `json:"category"`    // 特征类别
	CreateTime  string  `json:"create_time"` // 创建时间
	UpdateTime  string  `json:"update_time"` // 更新时间
}

// Manager 特征库管理器
type Manager struct {
	db         *sql.DB
	signatures []Signature
	updateURL  string
	mu         sync.RWMutex
	lastUpdate time.Time
	dbPath     string
}

// NewManager 创建特征库管理器
func NewManager(dbPath string) (*Manager, error) {
	// 确保数据库目录存在
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %v", err)
	}

	// 打开数据库连接
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// 初始化数据库表
	if err := initDatabase(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	mgr := &Manager{
		db:         db,
		signatures: make([]Signature, 0),
		updateURL:  "https://api.example.com/signatures/latest", // 替换为实际的更新服务器地址
		dbPath:     dbPath,
	}

	// 加载特征
	if err := mgr.loadSignatures(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to load signatures: %v", err)
	}

	return mgr, nil
}

// initDatabase 初始化数据库表
func initDatabase(db *sql.DB) error {
	createTable := `
	CREATE TABLE IF NOT EXISTS signatures (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pattern TEXT NOT NULL,
		type TEXT NOT NULL,
		description TEXT,
		weight REAL NOT NULL,
		category TEXT,
		create_time DATETIME DEFAULT CURRENT_TIMESTAMP,
		update_time DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_type ON signatures(type);
	CREATE INDEX IF NOT EXISTS idx_category ON signatures(category);
	`

	_, err := db.Exec(createTable)
	return err
}

// loadSignatures 从数据库加载特征
func (m *Manager) loadSignatures() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rows, err := m.db.Query(`
		SELECT id, pattern, type, description, weight, category, 
		       create_time, update_time 
		FROM signatures
	`)
	if err != nil {
		return fmt.Errorf("failed to query signatures: %v", err)
	}
	defer rows.Close()

	var signatures []Signature
	for rows.Next() {
		var sig Signature
		err := rows.Scan(
			&sig.ID,
			&sig.Pattern,
			&sig.Type,
			&sig.Description,
			&sig.Weight,
			&sig.Category,
			&sig.CreateTime,
			&sig.UpdateTime,
		)
		if err != nil {
			return fmt.Errorf("failed to scan signature: %v", err)
		}
		signatures = append(signatures, sig)
	}

	m.signatures = signatures
	m.lastUpdate = time.Now()
	return nil
}

// GetSignatures 获取所有特征
func (m *Manager) GetSignatures() []Signature {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.signatures
}

// AddSignature 添加新特征
func (m *Manager) AddSignature(sig Signature) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	result, err := m.db.Exec(`
		INSERT INTO signatures (pattern, type, description, weight, category)
		VALUES (?, ?, ?, ?, ?)
	`, sig.Pattern, sig.Type, sig.Description, sig.Weight, sig.Category)
	if err != nil {
		return fmt.Errorf("failed to insert signature: %v", err)
	}

	id, _ := result.LastInsertId()
	sig.ID = int(id)
	m.signatures = append(m.signatures, sig)
	return nil
}

// UpdateSignature 更新特征
func (m *Manager) UpdateSignature(sig Signature) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec(`
		UPDATE signatures 
		SET pattern = ?, type = ?, description = ?, 
		    weight = ?, category = ?, update_time = CURRENT_TIMESTAMP
		WHERE id = ?
	`, sig.Pattern, sig.Type, sig.Description, sig.Weight, sig.Category, sig.ID)
	if err != nil {
		return fmt.Errorf("failed to update signature: %v", err)
	}

	// 更新内存中的特征
	for i, s := range m.signatures {
		if s.ID == sig.ID {
			m.signatures[i] = sig
			break
		}
	}
	return nil
}

// DeleteSignature 删除特征
func (m *Manager) DeleteSignature(id int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM signatures WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete signature: %v", err)
	}

	// 从内存中删除特征
	for i, sig := range m.signatures {
		if sig.ID == id {
			m.signatures = append(m.signatures[:i], m.signatures[i+1:]...)
			break
		}
	}
	return nil
}

// CheckUpdate 检查特征库更新
func (m *Manager) CheckUpdate() (bool, error) {
	resp, err := http.Get(m.updateURL)
	if err != nil {
		return false, fmt.Errorf("failed to check update: %v", err)
	}
	defer resp.Body.Close()

	var latestVersion struct {
		Version   string    `json:"version"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&latestVersion); err != nil {
		return false, fmt.Errorf("failed to decode response: %v", err)
	}

	return latestVersion.UpdatedAt.After(m.lastUpdate), nil
}

// UpdateFromFile 从文件更新特征库
func (m *Manager) UpdateFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open update file: %v", err)
	}
	defer file.Close()

	return m.updateFromReader(file)
}

// UpdateFromURL 从URL更新特征库
func (m *Manager) UpdateFromURL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download update: %v", err)
	}
	defer resp.Body.Close()

	return m.updateFromReader(resp.Body)
}

// updateFromReader 从读取器更新特征库
func (m *Manager) updateFromReader(r io.Reader) error {
	var newSignatures []Signature
	if err := json.NewDecoder(r).Decode(&newSignatures); err != nil {
		return fmt.Errorf("failed to decode signatures: %v", err)
	}

	// 开始事务
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}

	// 清空现有特征
	if _, err := tx.Exec("DELETE FROM signatures"); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to clear signatures: %v", err)
	}

	// 插入新特征
	stmt, err := tx.Prepare(`
		INSERT INTO signatures (pattern, type, description, weight, category)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to prepare statement: %v", err)
	}
	defer stmt.Close()

	for _, sig := range newSignatures {
		_, err := stmt.Exec(sig.Pattern, sig.Type, sig.Description, sig.Weight, sig.Category)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to insert signature: %v", err)
		}
	}

	// 提交事务
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	// 重新加载特征
	return m.loadSignatures()
}

// Close 关闭特征库管理器
func (m *Manager) Close() error {
	return m.db.Close()
}
