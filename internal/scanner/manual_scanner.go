package scanner

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"webshell-detector/internal/config"
	"webshell-detector/internal/result"
	"webshell-detector/pkg/mlmodel"
	"webshell-detector/pkg/signature"
)

// ManualScanner 手动扫描器
type ManualScanner struct {
	*BaseScanner
	filePath string
}

// NewManualScanner 创建手动扫描器
func NewManualScanner(cfg *config.Config, sigMgr *signature.Manager, model *mlmodel.Model, filePath string) (*ManualScanner, error) {
	baseScanner := NewBaseScanner(cfg, sigMgr, model)
	return &ManualScanner{
		BaseScanner: baseScanner,
		filePath:    filePath,
	}, nil
}

// Start 开始扫描
func (s *ManualScanner) Start() error {
	if s.isRunning {
		return fmt.Errorf("scanner is already running")
	}

	s.isRunning = true
	startTime := time.Now()

	// 创建上下文
	ctx := context.Background()

	// 执行扫描
	detectionResult, err := s.detector.Detect(ctx, s.filePath)
	if err != nil {
		s.isRunning = false
		return fmt.Errorf("scan failed: %v", err)
	}

	// 创建结果打印器并打印结果
	printer := result.NewPrinter(true, true)
	printer.PrintResult(detectionResult)

	// 创建结果存储器
	storage, err := result.NewStorage("data/results.db")
	if err != nil {
		log.Printf("Warning: Failed to create result storage: %v", err)
	} else {
		defer storage.Close()
		// 存储扫描结果
		duration := time.Since(startTime)
		if err := storage.StoreResult(detectionResult, "manual", duration); err != nil {
			log.Printf("Warning: Failed to store result: %v", err)
		}
	}

	s.isRunning = false
	return nil
}

// Stop 停止扫描
func (s *ManualScanner) Stop() error {
	if !s.isRunning {
		return nil
	}
	s.isRunning = false
	return nil
}

// // scanDirectory 扫描目录
// func (s *ManualScanner) scanDirectory(dir string) {
// 	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
// 		if err != nil {
// 			return err
// 		}

// 		if info.IsDir() {
// 			// 检查是否在排除目录列表中
// 			for _, excludeDir := range s.config.Scan.ExcludeDirs {
// 				if path == excludeDir {
// 					return filepath.SkipDir
// 				}
// 			}
// 			return nil
// 		}

// 		// 检查文件扩展名
// 		ext := filepath.Ext(path)
// 		for _, fileType := range s.config.Scan.FileTypes {
// 			if ext == fileType {
// 				s.waitGroup.Add(1)
// 				go func(filePath string) {
// 					defer s.waitGroup.Done()
// 					s.workerPool <- struct{}{}        // 获取工作槽
// 					defer func() { <-s.workerPool }() // 释放工作槽

// 					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
// 					defer cancel()

// 					if err := s.Scan(ctx, filePath); err != nil {
// 						log.Printf("Error scanning file %s: %v", filePath, err)
// 					}
// 				}(path)
// 				break
// 			}
// 		}

// 		return nil
// 	})

// 	if err != nil {
// 		log.Printf("Error walking directory %s: %v", dir, err)
// 	}
// }

// scanSingleFile 扫描单个文件
func (s *ManualScanner) scanSingleFile(filePath string) {
	// 检查文件扩展名
	ext := filepath.Ext(filePath)
	validExt := false
	for _, fileType := range s.config.Scan.FileTypes {
		if ext == fileType {
			validExt = true
			break
		}
	}

	if !validExt {
		log.Printf("Unsupported file type: %s", filePath)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := s.Scan(ctx, filePath); err != nil {
		log.Printf("Error scanning file %s: %v", filePath, err)
	}
}
