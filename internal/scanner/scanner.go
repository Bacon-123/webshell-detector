/*
 * @Author: Mr.wpl
 * @Date: 2025-02-28 22:27:46
 * @Description:
 */
package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
	"webshell-detector/internal/config"
	"webshell-detector/internal/detector"
	"webshell-detector/internal/result"
	"webshell-detector/pkg/mlmodel"
	"webshell-detector/pkg/signature"
)

// Scanner 定义扫描器接口
type Scanner interface {
	Start() error
	Stop() error
	Scan(ctx context.Context, path string) error
}

// BaseScanner 提供基础扫描功能
type BaseScanner struct {
	config    *config.Config
	sigMgr    *signature.Manager
	detector  *detector.Detector
	isRunning bool
}

// NewBaseScanner 创建基础扫描器
func NewBaseScanner(cfg *config.Config, sigMgr *signature.Manager, model *mlmodel.Model) *BaseScanner {
	return &BaseScanner{
		config:    cfg,
		sigMgr:    sigMgr,
		detector:  detector.NewDetector(cfg, sigMgr, model),
		isRunning: false,
	}
}

// Scan 执行文件扫描
func (s *BaseScanner) Scan(ctx context.Context, path string) error {
	// 检查文件是否存在
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("file not found: %v", err)
	}

	// 使用检测器执行扫描
	detectionResult, err := s.detector.Detect(ctx, path)
	if err != nil {
		return fmt.Errorf("detection failed: %v", err)
	}

	// 创建结果打印器
	printer := result.NewPrinter(true, true)

	// 打印检测结果
	printer.PrintResult(detectionResult)

	// 创建结果存储器
	storage, err := result.NewStorage("data/results.db")
	if err != nil {
		log.Printf("Warning: Failed to create result storage: %v", err)
	} else {
		defer storage.Close()
		// 存储扫描结果
		if err := storage.StoreResult(detectionResult, "manual", time.Since(time.Now())); err != nil {
			log.Printf("Warning: Failed to store result: %v", err)
		}
	}

	// 如果检测到 webshell，返回错误
	if detectionResult.IsWebshell {
		return fmt.Errorf("webshell detected in file: %s", path)
	}

	return nil
}

// Stop 停止扫描
func (s *BaseScanner) Stop() error {
	if !s.isRunning {
		return nil
	}
	s.isRunning = false
	return nil
}
