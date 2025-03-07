package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"webshell-detector/internal/config"
	"webshell-detector/internal/scanner"
	"webshell-detector/pkg/mlmodel"
	"webshell-detector/pkg/signature"
)

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "configs/config.yaml", "Path to config file")
	filePath := flag.String("file", "", "Path to file to scan")
	scanMode := flag.String("mode", "manual", "Scan mode: manual/realtime/scheduled")
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 初始化特征库
	sigMgr, err := signature.NewManager(cfg.SignaturePath)
	if err != nil {
		log.Fatalf("Failed to initialize signature manager: %v", err)
	}
	defer sigMgr.Close()

	// 初始化机器学习模型
	model, err := mlmodel.LoadModel(cfg.ModelPath)
	if err != nil {
		log.Printf("Warning: Failed to load ML model: %v", err)
	}

	// 根据扫描模式选择不同的操作
	switch *scanMode {
	case "manual":
		if *filePath == "" {
			log.Fatal("Please specify a file to scan using -file flag")
		}
		// 执行单文件扫描
		handleManualScan(cfg, sigMgr, model, *filePath)

	case "realtime":
		// 启动实时扫描
		handleRealtimeScan(cfg, sigMgr, model)

	case "scheduled":
		// 启动定时扫描
		handleScheduledScan(cfg, sigMgr, model)

	default:
		log.Fatalf("Unknown scan mode: %s", *scanMode)
	}
}

// handleManualScan 处理单文件扫描
func handleManualScan(cfg *config.Config, sigMgr *signature.Manager, model *mlmodel.Model, filePath string) {
	startTime := time.Now()

	// 创建手动扫描器
	manualScanner, err := scanner.NewManualScanner(cfg, sigMgr, model, filePath)
	if err != nil {
		log.Fatalf("Failed to create manual scanner: %v", err)
	}

	// 执行扫描
	if err := manualScanner.Start(); err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// 等待扫描完成
	if err := manualScanner.Stop(); err != nil {
		log.Fatalf("Failed to stop scanner: %v", err)
	}

	// 打印扫描耗时
	fmt.Printf("\nScan completed in %v\n", time.Since(startTime))
}

// handleRealtimeScan 处理实时扫描
func handleRealtimeScan(cfg *config.Config, sigMgr *signature.Manager, model *mlmodel.Model) {
	realtimeScanner, err := scanner.NewRealtimeScanner(cfg, sigMgr, model)
	if err != nil {
		log.Fatalf("Failed to create realtime scanner: %v", err)
	}

	log.Println("Starting realtime scan...")
	if err := realtimeScanner.Start(); err != nil {
		log.Fatalf("Failed to start realtime scan: %v", err)
	}

	// 等待中断信号
	select {}
}

// handleScheduledScan 处理定时扫描
func handleScheduledScan(cfg *config.Config, sigMgr *signature.Manager, model *mlmodel.Model) {
	scheduledScanner, err := scanner.NewScheduledScanner(cfg, sigMgr, model)
	if err != nil {
		log.Fatalf("Failed to create scheduled scanner: %v", err)
	}

	log.Println("Starting scheduled scan...")
	if err := scheduledScanner.Start(); err != nil {
		log.Fatalf("Failed to start scheduled scan: %v", err)
	}

	// 等待中断信号
	select {}
}
