package detector

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// BehaviorAnalysisResult 行为分析结果
type BehaviorAnalysisResult struct {
	Score     float64
	Behaviors []string
}

// behaviorAnalyze 执行行为分析检测
func (d *Detector) behaviorAnalyze(ctx context.Context, filePath string, content []byte) (*BehaviorAnalysisResult, error) {
	result := &BehaviorAnalysisResult{
		Score:     0, // 初始分数为0，只有发现可疑行为才增加分数
		Behaviors: make([]string, 0),
	}

	// 创建临时沙箱环境
	sandboxDir, err := os.MkdirTemp("", "webshell-sandbox-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox: %v", err)
	}
	defer os.RemoveAll(sandboxDir)

	// 复制文件到沙箱
	sandboxFile := filepath.Join(sandboxDir, filepath.Base(filePath))
	if err := os.WriteFile(sandboxFile, content, 0644); err != nil {
		return nil, fmt.Errorf("failed to copy file to sandbox: %v", err)
	}

	// 设置超时上下文
	timeout := time.Duration(d.config.Detection.BehaviorAnalysis.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 使用strace监控系统调用
	cmd := exec.CommandContext(ctx, "strace", "-f", "-e", "trace=process,file,network", "php", sandboxFile)
	cmd.Dir = sandboxDir
	output, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(err.Error(), "exit status") {
		return nil, fmt.Errorf("failed to analyze behavior: %v", err)
	}

	// 分析系统调用
	straceOutput := string(output)

	// 检测危险的文件操作
	dangerousFileOps := map[string]struct {
		score    float64
		behavior string
	}{
		"unlink(":  {score: 30, behavior: "Attempted to delete files"},
		"rmdir(":   {score: 20, behavior: "Attempted to delete directories"},
		"chmod(":   {score: 20, behavior: "Attempted to change file permissions"},
		"chown(":   {score: 20, behavior: "Attempted to change file ownership"},
		"symlink(": {score: 15, behavior: "Attempted to create symbolic links"},
		"rename(":  {score: 10, behavior: "Attempted to rename files"},
	}

	for pattern, action := range dangerousFileOps {
		if strings.Contains(straceOutput, pattern) {
			if !strings.Contains(straceOutput, "/tmp/") && !strings.Contains(straceOutput, "/var/cache/") {
				result.Score += math.Abs(action.score) // 使用正数增加分数
				result.Behaviors = append(result.Behaviors, action.behavior)
			}
		}
	}

	// 检测网络连接
	if strings.Contains(straceOutput, "connect(") {
		// 排除本地连接和正常的PHP扩展连接
		if !strings.Contains(straceOutput, "127.0.0.1") && !strings.Contains(straceOutput, "localhost") {
			result.Score += 20
			result.Behaviors = append(result.Behaviors, "Attempted to establish external network connection")
		}
	}

	// 检测进程创建
	dangerousCommands := []string{
		"sh", "bash", "cmd", "powershell", "nc", "netcat", "curl", "wget", "telnet",
	}
	for _, cmd := range dangerousCommands {
		if strings.Contains(strings.ToLower(straceOutput), fmt.Sprintf("execve(\"%s\"", cmd)) {
			result.Score += 25
			result.Behaviors = append(result.Behaviors, fmt.Sprintf("Attempted to execute dangerous command: %s", cmd))
		}
	}

	// 检测敏感文件访问
	sensitiveFiles := map[string]struct {
		score    float64
		behavior string
	}{
		"/etc/passwd": {score: 15, behavior: "Attempted to access password file"},
		"/etc/shadow": {score: 25, behavior: "Attempted to access shadow password file"},
		"/etc/hosts":  {score: 10, behavior: "Attempted to access hosts file"},
		"/proc/":      {score: 15, behavior: "Attempted to access process information"},
		"/dev/":       {score: 20, behavior: "Attempted to access device files"},
	}

	for file, action := range sensitiveFiles {
		if strings.Contains(straceOutput, fmt.Sprintf(`open("%s`, file)) {
			result.Score += action.score
			result.Behaviors = append(result.Behaviors, action.behavior)
		}
	}

	// 只有当发现可疑行为时才有分数
	if len(result.Behaviors) == 0 {
		result.Score = 0
	}

	// 归一化分数
	if result.Score > 100 {
		result.Score = 100
	}

	return result, nil
}
