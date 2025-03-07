/*
 * @Author: Mr.wpl
 * @Date: 2025-02-28 22:54:19
 * @Description:
 */
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"webshell-detector/internal/config"
	"webshell-detector/internal/detector"
)

// SMSAlert 短信告警实现
type SMSAlert struct {
	config config.SMSConfig
	client *http.Client
}

// NewSMSAlert 创建短信告警
func NewSMSAlert(cfg config.SMSConfig) *SMSAlert {
	return &SMSAlert{
		config: cfg,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsEnabled 检查是否启用
func (s *SMSAlert) IsEnabled() bool {
	return s.config.Enabled
}

// Send 发送短信告警
func (s *SMSAlert) Send(result *detector.DetectionResult) error {
	// 生成短信内容
	message := fmt.Sprintf(
		s.config.Template,
		result.FilePath,
		result.RiskLevel,
	)

	// 准备请求数据
	requestData := map[string]interface{}{
		"api_key":     s.config.APIKey,
		"message":     message,
		"phone_list":  s.config.PhoneList,
		"risk_level":  result.RiskLevel,
		"total_score": result.TotalScore,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return fmt.Errorf("failed to marshal request data: %v", err)
	}

	// 发送HTTP请求
	req, err := http.NewRequest("POST", s.config.Gateway, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SMS request: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		var errorResponse struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&errorResponse); err != nil {
			return fmt.Errorf("SMS gateway returned status %d", resp.StatusCode)
		}
		return fmt.Errorf("SMS gateway error: %s", errorResponse.Error)
	}

	return nil
}
