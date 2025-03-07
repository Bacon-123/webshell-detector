package detector

import (
	"context"
	"fmt"
	"os"
	"sync"

	"webshell-detector/internal/config"
	"webshell-detector/pkg/mlmodel"
	"webshell-detector/pkg/signature"
)

// DetectionResult 检测结果结构
type DetectionResult struct {
	FilePath        string
	IsWebshell      bool
	RiskLevel       RiskLevel
	FeatureScore    float64
	BehaviorScore   float64
	MLScore         float64
	MatchedFeatures []string
	Behaviors       []string
	TotalScore      float64
}

// RiskLevel 风险等级
type RiskLevel string

const (
	RiskLevelHigh   RiskLevel = "HIGH"
	RiskLevelMedium RiskLevel = "MEDIUM"
	RiskLevelLow    RiskLevel = "LOW"
	RiskLevelSafe   RiskLevel = "SAFE"
)

// Detector 检测器结构
type Detector struct {
	config     *config.Config
	sigMgr     *signature.Manager
	mlModel    *mlmodel.Model
	resultChan chan *DetectionResult
	mu         sync.Mutex
}

// NewDetector 创建新的检测器
func NewDetector(cfg *config.Config, sigMgr *signature.Manager, mlModel *mlmodel.Model) *Detector {
	return &Detector{
		config:     cfg,
		sigMgr:     sigMgr,
		mlModel:    mlModel,
		resultChan: make(chan *DetectionResult, 100),
	}
}

// Detect 执行文件检测
func (d *Detector) Detect(ctx context.Context, filePath string) (*DetectionResult, error) {
	fmt.Println("\nStarting detection process...")

	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	result := &DetectionResult{
		FilePath: filePath,
	}

	// 特征匹配检测
	fmt.Println("1. Running feature matching analysis...")
	featureResult, err := d.featureMatch(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("feature matching failed: %v", err)
	}
	result.FeatureScore = featureResult.Score
	result.MatchedFeatures = featureResult.Matches

	// 行为分析检测
	if d.config.Detection.BehaviorAnalysis.Enabled {
		fmt.Println("2. Running behavior analysis...")
		behaviorResult, err := d.behaviorAnalyze(ctx, filePath, content)
		if err != nil {
			fmt.Printf("Warning: Behavior analysis failed: %v\n", err)
		} else {
			result.BehaviorScore = behaviorResult.Score
			result.Behaviors = behaviorResult.Behaviors
		}
	}

	// 机器学习检测
	if d.config.Detection.MachineLearning.Enabled {
		fmt.Println("3. Running machine learning analysis...")
		mlScore, err := d.mlDetect(ctx, content)
		if err != nil {
			fmt.Printf("Warning: ML detection failed: %v\n", err)
		} else {
			result.MLScore = mlScore
		}
	}

	// 计算总分并确定风险等级
	d.calculateTotalScore(result)
	fmt.Println("Detection process completed.")

	return result, nil
}

// calculateTotalScore 计算总分并确定风险等级
func (d *Detector) calculateTotalScore(result *DetectionResult) {
	// 特征匹配权重更高，因为它更可靠
	weights := map[string]float64{
		"feature":  0.5, // 特征匹配权重50%
		"behavior": 0.3, // 行为分析权重30%
		"ml":       0.2, // 机器学习权重20%
	}

	totalScore := 0.0
	totalWeight := weights["feature"]
	totalScore += result.FeatureScore * weights["feature"]

	if d.config.Detection.BehaviorAnalysis.Enabled {
		// 如果行为分析没有发现可疑行为，分数应该为0而不是100
		if len(result.Behaviors) == 0 {
			result.BehaviorScore = 0
		}
		totalScore += result.BehaviorScore * weights["behavior"]
		totalWeight += weights["behavior"]
	}

	if d.config.Detection.MachineLearning.Enabled {
		// 如果所有特征都是安全的，ML分数应该较低
		if result.FeatureScore == 0 && len(result.Behaviors) == 0 {
			result.MLScore = result.MLScore * 0.1 // 大幅降低ML分数的影响
		}
		totalScore += result.MLScore * weights["ml"]
		totalWeight += weights["ml"]
	}

	// 计算加权平均分
	result.TotalScore = totalScore / totalWeight

	// 调整风险等级阈值和评分逻辑
	switch {
	case result.TotalScore >= 85: // 提高高风险阈值
		result.RiskLevel = RiskLevelHigh
		result.IsWebshell = true
	case result.TotalScore >= 70: // 提高中风险阈值
		result.RiskLevel = RiskLevelMedium
		result.IsWebshell = result.FeatureScore > 80 // 只有特征分高才判定为webshell
	case result.TotalScore >= 40:
		result.RiskLevel = RiskLevelLow
		result.IsWebshell = false
	default:
		result.RiskLevel = RiskLevelSafe
		result.IsWebshell = false
	}

	// 如果特征匹配发现明显的webshell特征,直接标记
	if result.FeatureScore > 90 {
		result.IsWebshell = true
		result.RiskLevel = RiskLevelHigh
	}

	// 如果特征匹配和行为分析都没有发现问题，强制设为安全
	if result.FeatureScore == 0 && len(result.Behaviors) == 0 {
		result.RiskLevel = RiskLevelSafe
		result.IsWebshell = false
		if result.TotalScore > 30 {
			result.TotalScore = 30
		}
	}
}
