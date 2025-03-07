package mlmodel

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ModelData 模型数据结构
type ModelData struct {
	Weights      []float64 `json:"weights"`
	Threshold    float64   `json:"threshold"`
	FeatureCount int       `json:"feature_count"`
}

// Model 机器学习模型结构
type Model struct {
	Path         string
	LastUpdate   time.Time
	FeatureCount int
	ModelData    *ModelData
	Threshold    float64
	mu           sync.RWMutex
}

// LoadModel 加载机器学习模型
func LoadModel(modelPath string) (*Model, error) {
	file, err := os.ReadFile(modelPath) // 读取整个文件
	if err != nil {
		return nil, fmt.Errorf("failed to open model file: %v", err)
	}

	var modelData ModelData
	if err := json.Unmarshal(file, &modelData); err != nil {
		return nil, fmt.Errorf("failed to decode model: %v", err)
	}

	model := &Model{
		Path:         modelPath,
		LastUpdate:   time.Now(),
		FeatureCount: modelData.FeatureCount,
		ModelData:    &modelData,
		Threshold:    modelData.Threshold,
	}

	return model, nil
}

// Predict 使用模型进行预测
func (m *Model) Predict(features []float64) (float64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(features) != m.FeatureCount {
		return 0, fmt.Errorf("invalid feature count: expected %d, got %d", m.FeatureCount, len(features))
	}

	// 使用加载的权重进行预测
	score := 0.0
	for i, feature := range features {
		score += feature * m.ModelData.Weights[i]
	}

	// 归一化得分到 0-1 范围
	if score > 1.0 {
		score = 1.0
	} else if score < 0.0 {
		score = 0.0
	}

	return score, nil
}

// UpdateModel 更新模型
func (m *Model) UpdateModel(newModelPath string) error {
	// 创建备份
	backupPath := m.Path + ".backup"
	if err := copyFile(m.Path, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %v", err)
	}

	// 加载新模型
	file, err := os.ReadFile(newModelPath)
	if err != nil {
		return fmt.Errorf("failed to open new model file: %v", err)
	}

	var newModelData ModelData
	if err := json.Unmarshal(file, &newModelData); err != nil {
		// 恢复备份
		if restoreErr := copyFile(backupPath, m.Path); restoreErr != nil {
			return fmt.Errorf("failed to decode new model and restore backup: %v, %v", err, restoreErr)
		}
		return fmt.Errorf("failed to decode new model: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// 复制新模型到原位置
	if err := copyFile(newModelPath, m.Path); err != nil {
		return fmt.Errorf("failed to copy new model: %v", err)
	}

	// 更新模型数据
	m.ModelData = &newModelData
	m.LastUpdate = time.Now()
	m.FeatureCount = newModelData.FeatureCount
	m.Threshold = newModelData.Threshold

	// 删除备份
	os.Remove(backupPath)

	return nil
}

// SetThreshold 设置预测阈值
func (m *Model) SetThreshold(threshold float64) error {
	if threshold < 0 || threshold > 1 {
		return fmt.Errorf("threshold must be between 0 and 1")
	}

	m.mu.Lock()
	m.Threshold = threshold
	m.mu.Unlock()

	return nil
}

// GetModelInfo 获取模型信息
func (m *Model) GetModelInfo() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"path":          m.Path,
		"last_update":   m.LastUpdate,
		"feature_count": m.FeatureCount,
		"threshold":     m.Threshold,
	}
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = destFile.ReadFrom(sourceFile)
	return err
}
