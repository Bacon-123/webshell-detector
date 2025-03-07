package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 系统总配置结构
type Config struct {
	// 扫描配置
	Scan ScanConfig `yaml:"scan"`
	// 检测配置
	Detection DetectionConfig `yaml:"detection"`
	// 告警配置
	Alert AlertConfig `yaml:"alert"`
	// 存储配置
	Storage StorageConfig `yaml:"storage"`
	// 路径配置
	SignaturePath string `yaml:"signature_path"` // 特征库路径
	ModelPath     string `yaml:"model_path"`     // 机器学习模型路径
}

// ScanConfig 扫描相关配置
type ScanConfig struct {
	// 扫描目录配置
	Directories []string `yaml:"directories"`  // 需要扫描的目录列表
	ExcludeDirs []string `yaml:"exclude_dirs"` // 排除的目录列表

	// 定时扫描配置
	Schedule ScheduleConfig `yaml:"schedule"`

	// 实时扫描配置
	Realtime RealtimeConfig `yaml:"realtime"`

	// 文件类型配置
	FileTypes []string `yaml:"file_types"` // 需要扫描的文件类型，如 [".php", ".jsp", ".asp"]
}

// ScheduleConfig 定时扫描配置
type ScheduleConfig struct {
	Enabled     bool          `yaml:"enabled"`      // 是否启用定时扫描
	Interval    time.Duration `yaml:"interval"`     // 扫描间隔
	StartTime   string        `yaml:"start_time"`   // 首次扫描时间
	MaxFileSize int64         `yaml:"max_filesize"` // 最大文件大小限制(bytes)
}

// RealtimeConfig 实时扫描配置
type RealtimeConfig struct {
	Enabled        bool `yaml:"enabled"`         // 是否启用实时扫描
	MaxConcurrency int  `yaml:"max_concurrency"` // 最大并发扫描数
}

// DetectionConfig 检测算法相关配置
type DetectionConfig struct {
	// 特征匹配配置
	FeatureMatch struct {
		MinScore float64 `yaml:"min_score"` // 最小匹配分数
		MaxScore float64 `yaml:"max_score"` // 最大匹配分数
	} `yaml:"feature_match"`

	// 行为分析配置
	BehaviorAnalysis struct {
		Enabled     bool  `yaml:"enabled"`    // 是否启用行为分析
		Timeout     int64 `yaml:"timeout"`    // 行为分析超时时间(秒)
		MaxMemoryMB int64 `yaml:"max_memory"` // 最大内存限制(MB)
	} `yaml:"behavior_analysis"`

	// 机器学习配置
	MachineLearning struct {
		Enabled   bool    `yaml:"enabled"`    // 是否启用机器学习检测
		Threshold float64 `yaml:"threshold"`  // 检测阈值
		BatchSize int     `yaml:"batch_size"` // 批处理大小
	} `yaml:"machine_learning"`

	// YARA配置
	Yara YaraConfig `yaml:"yara"`
}

// AlertConfig 告警相关配置
type AlertConfig struct {
	// 告警阈值配置
	Threshold struct {
		HighRisk   float64 `yaml:"high_risk"`   // 高风险阈值
		MediumRisk float64 `yaml:"medium_risk"` // 中风险阈值
		LowRisk    float64 `yaml:"low_risk"`    // 低风险阈值
	} `yaml:"threshold"`

	// 邮件告警配置
	Email struct {
		Enabled  bool     `yaml:"enabled"`  // 是否启用邮件告警
		Host     string   `yaml:"host"`     // SMTP服务器地址
		Port     int      `yaml:"port"`     // SMTP服务器端口
		Username string   `yaml:"username"` // SMTP用户名
		Password string   `yaml:"password"` // SMTP密码
		From     string   `yaml:"from"`     // 发件人地址
		To       []string `yaml:"to"`       // 收件人地址列表
	} `yaml:"email"`

	// 短信告警配置
	SMS struct {
		Enabled   bool     `yaml:"enabled"`  // 是否启用短信告警
		Gateway   string   `yaml:"gateway"`  // 短信网关地址
		APIKey    string   `yaml:"api_key"`  // API密钥
		Template  string   `yaml:"template"` // 短信模板
		PhoneList []string `yaml:"phones"`   // 接收手机号列表
	} `yaml:"sms"`
}

// StorageConfig 存储相关配置
type StorageConfig struct {
	// 数据库配置
	Database struct {
		Type     string `yaml:"type"`     // 数据库类型(sqlite/postgresql)
		Path     string `yaml:"path"`     // 数据库文件路径(sqlite)
		Host     string `yaml:"host"`     // 数据库主机地址
		Port     int    `yaml:"port"`     // 数据库端口
		Name     string `yaml:"name"`     // 数据库名称
		Username string `yaml:"username"` // 数据库用户名
		Password string `yaml:"password"` // 数据库密码
	} `yaml:"database"`

	// 历史记录保留配置
	History struct {
		RetentionDays int   `yaml:"retention_days"` // 历史记录保留天数
		MaxRecords    int64 `yaml:"max_records"`    // 最大记录数
	} `yaml:"history"`
}

// YaraConfig YARA配置
type YaraConfig struct {
	Enabled     bool     `yaml:"enabled"`       // 是否启用YARA检测
	RulesDir    string   `yaml:"rules_dir"`     // 规则目录
	RuleTypes   []string `yaml:"rule_types"`    // 要检测的规则类型
	MaxFileSize int64    `yaml:"max_file_size"` // 最大扫描文件大小
}

// LoadConfig 从指定路径加载配置文件
func LoadConfig(path string) (*Config, error) {
	// 读取配置文件
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	// 解析配置文件
	config := &Config{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// 验证配置
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// validateConfig 验证配置是否有效
func validateConfig(cfg *Config) error {
	// 验证扫描目录
	if len(cfg.Scan.Directories) == 0 {
		return fmt.Errorf("no scan directories specified")
	}

	// 验证文件类型
	if len(cfg.Scan.FileTypes) == 0 {
		return fmt.Errorf("no file types specified")
	}

	// 验证特征库路径
	if cfg.SignaturePath == "" {
		return fmt.Errorf("signature path is required")
	}

	// 验证机器学习模型路径
	if cfg.Detection.MachineLearning.Enabled && cfg.ModelPath == "" {
		return fmt.Errorf("model path is required when machine learning is enabled")
	}

	// 验证告警配置
	if cfg.Alert.Email.Enabled {
		if cfg.Alert.Email.Host == "" || cfg.Alert.Email.Port == 0 {
			return fmt.Errorf("invalid email configuration")
		}
		if len(cfg.Alert.Email.To) == 0 {
			return fmt.Errorf("no email recipients specified")
		}
	}

	if cfg.Alert.SMS.Enabled {
		if cfg.Alert.SMS.Gateway == "" || cfg.Alert.SMS.APIKey == "" {
			return fmt.Errorf("invalid SMS configuration")
		}
		if len(cfg.Alert.SMS.PhoneList) == 0 {
			return fmt.Errorf("no SMS recipients specified")
		}
	}

	return nil
}
