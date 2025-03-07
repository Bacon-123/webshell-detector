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

	"github.com/fsnotify/fsnotify"
)

// RealtimeScanner 实时扫描器
type RealtimeScanner struct {
	*BaseScanner
	watcher    *fsnotify.Watcher
	workerPool chan struct{}
	waitGroup  sync.WaitGroup
}

// NewRealtimeScanner 创建实时扫描器
func NewRealtimeScanner(cfg *config.Config, sigMgr *signature.Manager, mlModel *mlmodel.Model) (*RealtimeScanner, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %v", err)
	}

	scanner := &RealtimeScanner{
		BaseScanner: NewBaseScanner(cfg, sigMgr, mlModel),
		watcher:     watcher,
		workerPool:  make(chan struct{}, cfg.Scan.Realtime.MaxConcurrency),
	}

	return scanner, nil
}

// Start 启动实时扫描
func (s *RealtimeScanner) Start() error {
	if !s.config.Scan.Realtime.Enabled {
		return fmt.Errorf("realtime scanning is disabled in configuration")
	}

	if s.isRunning {
		return fmt.Errorf("scanner is already running")
	}

	s.isRunning = true

	// 添加监控目录
	for _, dir := range s.config.Scan.Directories {
		if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				// 检查是否在排除目录列表中
				for _, excludeDir := range s.config.Scan.ExcludeDirs {
					if path == excludeDir {
						return filepath.SkipDir
					}
				}
				return s.watcher.Add(path)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to add directory to watcher: %v", err)
		}
	}

	// 启动文件监控
	go s.watch()

	return nil
}

// Stop 停止实时扫描
func (s *RealtimeScanner) Stop() error {
	if !s.isRunning {
		return nil
	}

	s.isRunning = false
	s.waitGroup.Wait()
	return s.watcher.Close()
}

// watch 监控文件变化
func (s *RealtimeScanner) watch() {
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}

			// 检查文件操作类型
			if event.Op&(fsnotify.Create|fsnotify.Write) == 0 {
				continue
			}

			// 检查文件扩展名
			ext := filepath.Ext(event.Name)
			validExt := false
			for _, fileType := range s.config.Scan.FileTypes {
				if ext == fileType {
					validExt = true
					break
				}
			}
			if !validExt {
				continue
			}

			// 启动扫描任务
			s.waitGroup.Add(1)
			go func(path string) {
				defer s.waitGroup.Done()
				s.workerPool <- struct{}{}        // 获取工作槽
				defer func() { <-s.workerPool }() // 释放工作槽

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()

				if err := s.Scan(ctx, path); err != nil {
					log.Printf("Error scanning file %s: %v", path, err)
				}
			}(event.Name)

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}
