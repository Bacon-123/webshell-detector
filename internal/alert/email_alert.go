package alert

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strings"
	"time"

	"webshell-detector/internal/config"
	"webshell-detector/internal/detector"
)

// EmailAlert 邮件告警实现
type EmailAlert struct {
	config config.EmailConfig
	auth   smtp.Auth
}

// NewEmailAlert 创建邮件告警
func NewEmailAlert(cfg config.EmailConfig) *EmailAlert {
	auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	return &EmailAlert{
		config: cfg,
		auth:   auth,
	}
}

// IsEnabled 检查是否启用
func (e *EmailAlert) IsEnabled() bool {
	return e.config.Enabled
}

// Send 发送邮件告警
func (e *EmailAlert) Send(result *detector.DetectionResult) error {
	// 生成邮件内容
	body, err := e.generateEmailBody(result)
	if err != nil {
		return fmt.Errorf("failed to generate email body: %v", err)
	}

	// 构建邮件头
	subject := fmt.Sprintf("Webshell Detection Alert - %s Risk Level", result.RiskLevel)
	message := bytes.NewBuffer(nil)
	message.WriteString(fmt.Sprintf("From: %s\r\n", e.config.From))
	message.WriteString(fmt.Sprintf("To: %s\r\n", e.config.To[0])) // 第一个收件人
	message.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	message.WriteString("MIME-Version: 1.0\r\n")
	message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	message.WriteString("\r\n")
	message.WriteString(body)

	// 配置TLS
	tlsConfig := &tls.Config{
		ServerName:         e.config.Host,
		InsecureSkipVerify: false,
	}

	// 连接SMTP服务器
	addr := fmt.Sprintf("%s:%d", e.config.Host, e.config.Port)
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, e.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer client.Close()

	// 认证
	if err := client.Auth(e.auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %v", err)
	}

	// 设置发件人和收件人
	if err := client.Mail(e.config.From); err != nil {
		return fmt.Errorf("failed to set sender: %v", err)
	}
	for _, to := range e.config.To {
		if err := client.Rcpt(to); err != nil {
			return fmt.Errorf("failed to set recipient %s: %v", to, err)
		}
	}

	// 发送邮件内容
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to create email writer: %v", err)
	}
	defer w.Close()

	if _, err := w.Write(message.Bytes()); err != nil {
		return fmt.Errorf("failed to write email content: %v", err)
	}

	return nil
}

// generateEmailBody 生成邮件内容
func (e *EmailAlert) generateEmailBody(result *detector.DetectionResult) (string, error) {
	const emailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .high { color: #ff0000; }
        .medium { color: #ffa500; }
        .low { color: #0000ff; }
        .details { margin: 20px 0; }
        .features { margin: 10px 0; }
    </style>
</head>
<body>
    <h2>Webshell Detection Alert</h2>
    <p>A potential webshell has been detected:</p>
    <ul>
        <li><strong>File:</strong> {{.FilePath}}</li>
        <li><strong>Risk Level:</strong> <span class="{{.RiskLevelClass}}">{{.RiskLevel}}</span></li>
        <li><strong>Detection Time:</strong> {{.Time}}</li>
        <li><strong>Total Score:</strong> {{printf "%.2f" .TotalScore}}</li>
    </ul>
    
    <div class="details">
        <h3>Detection Details:</h3>
        <ul>
            <li>Feature Score: {{printf "%.2f" .FeatureScore}}</li>
            <li>Behavior Score: {{printf "%.2f" .BehaviorScore}}</li>
            <li>ML Score: {{printf "%.2f" .MLScore}}</li>
        </ul>
    </div>

    {{if .MatchedFeatures}}
    <div class="features">
        <h3>Matched Features:</h3>
        <ul>
            {{range .MatchedFeatures}}
            <li>{{.}}</li>
            {{end}}
        </ul>
    </div>
    {{end}}

    {{if .Behaviors}}
    <div class="features">
        <h3>Suspicious Behaviors:</h3>
        <ul>
            {{range .Behaviors}}
            <li>{{.}}</li>
            {{end}}
        </ul>
    </div>
    {{end}}
</body>
</html>`

	// 准备模板数据
	data := struct {
		*detector.DetectionResult
		Time           string
		RiskLevelClass string
	}{
		DetectionResult: result,
		Time:            time.Now().Format("2006-01-02 15:04:05"),
		RiskLevelClass:  strings.ToLower(string(result.RiskLevel)),
	}

	// 解析并执行模板
	tmpl, err := template.New("email").Parse(emailTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
