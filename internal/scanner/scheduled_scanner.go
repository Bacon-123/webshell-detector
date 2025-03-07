package scanner

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"webshell-detector/internal/config"
	"webshell-detector/pkg/mlmodel"
	"webshell-detector/pkg/signature"
)

// ScheduledScanner 定时扫描器
type ScheduledScanner struct {
	*BaseScanner
	ticker     *time.Ticker
	workerPool chan struct{}
	waitGroup  sync.WaitGroup
}

// NewScheduledScanner 创建定时扫描器
func NewScheduledScanner(cfg *config.Config, sigMgr *signature.Manager, mlModel *mlmodel.Model) (*ScheduledScanner, error) {
	scanner := &ScheduledScanner{
		BaseScanner: NewBaseScanner(cfg, sigMgr, mlModel),
		workerPool:  make(chan struct{}, cfg.Scan.Realtime.MaxConcurrency),
	}
	return scanner, nil
}

// Start 启动定时扫描
func (s *ScheduledScanner) Start() error {
	if !s.config.Scan.Schedule.Enabled {
		return fmt.Errorf("scheduled scanning is disabled in configuration")
	}

	if s.isRunning {
		return fmt.Errorf("scanner is already running")
	}

	s.isRunning = true

	// 解析首次扫描时间
	startTime, err := time.Parse("15:04", s.config.Scan.Schedule.StartTime)
	if err != nil {
		return fmt.Errorf("invalid start time format: %v", err)
	}

	// 计算首次扫描的延迟时间
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), startTime.Hour(), startTime.Minute(), 0, 0, now.Location())
	if today.Before(now) {
		today = today.Add(24 * time.Hour)
	}
	delay := today.Sub(now)

	// 创建定时器
	s.ticker = time.NewTicker(s.config.Scan.Schedule.Interval)

	// 启动定时扫描
	go func() {
		// 等待首次扫描时间
		time.Sleep(delay)

		// 执行首次扫描
		s.scanAll()

		// 按间隔执行后续扫描
		for range s.ticker.C {
			if !s.isRunning {
				return
			}
			s.scanAll()
		}
	}()

	return nil
}

// Stop 停止定时扫描
func (s *ScheduledScanner) Stop() error {
	if !s.isRunning {
		return nil
	}

	s.isRunning = false
	if s.ticker != nil {
		s.ticker.Stop()
	}
	s.waitGroup.Wait()
	return nil
}

// scanAll 扫描所有配置的目录
func (s *ScheduledScanner) scanAll() {
	for _, dir := range s.config.Scan.Directories {
		s.scanDirectory(dir)
	}
}

// scanDirectory 扫描指定目录
func (s *ScheduledScanner) scanDirectory(dir string) {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 检查是否是目录
		if info.IsDir() {
			// 检查是否在排除目录列表中
			for _, excludeDir := range s.config.Scan.ExcludeDirs {
				if path == excludeDir {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// 检查文件大小
		if info.Size() > s.config.Scan.Schedule.MaxFileSize {
			return nil
		}

		// 检查文件扩展名
		ext := filepath.Ext(path)
		for _, fileType := range s.config.Scan.FileTypes {
			if ext == fileType {
				s.waitGroup.Add(1)
				go func(filePath string) {
					defer s.waitGroup.Done()
					s.workerPool <- struct{}{}        // 获取工作槽
					defer func() { <-s.workerPool }() // 释放工作槽

					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
					defer cancel()

					if err := s.Scan(ctx, filePath); err != nil {
						log.Printf("Error scanning file %s: %v", filePath, err)
					}
				}(path)
				break
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Error walking directory %s: %v", dir, err)
	}
}
