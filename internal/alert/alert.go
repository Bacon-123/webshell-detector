/*
 * @Author: Mr.wpl
 * @Date: 2025-02-28 22:53:53
 * @Description:
 */
package alert

import (
	"fmt"
	"sync"
	"time"

	"webshell-detector/internal/detector"
)

// AlertType 告警类型
type AlertType string

const (
	AlertTypeEmail AlertType = "email"
	AlertTypeSMS   AlertType = "sms"
)

// Alert 告警接口
type Alert interface {
	Send(result *detector.DetectionResult) error
	IsEnabled() bool
}

// Manager 告警管理器
type Manager struct {
	alerts     map[AlertType]Alert
	mu         sync.RWMutex
	rateLimit  time.Duration
	lastAlerts map[string]time.Time // 文件路径 -> 上次告警时间
}

// NewManager 创建告警管理器
func NewManager(rateLimit time.Duration) *Manager {
	return &Manager{
		alerts:     make(map[AlertType]Alert),
		rateLimit:  rateLimit,
		lastAlerts: make(map[string]time.Time),
	}
}

// RegisterAlert 注册告警方式
func (m *Manager) RegisterAlert(alertType AlertType, alert Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts[alertType] = alert
}

// SendAlert 发送告警
func (m *Manager) SendAlert(result *detector.DetectionResult) error {
	m.mu.Lock()
	// 检查告警频率限制
	if lastAlert, exists := m.lastAlerts[result.FilePath]; exists {
		if time.Since(lastAlert) < m.rateLimit {
			m.mu.Unlock()
			return fmt.Errorf("rate limit exceeded for %s", result.FilePath)
		}
	}
	m.lastAlerts[result.FilePath] = time.Now()
	m.mu.Unlock()

	var errs []error
	for _, alert := range m.alerts {
		if alert.IsEnabled() {
			if err := alert.Send(result); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("alert errors: %v", errs)
	}
	return nil
}
