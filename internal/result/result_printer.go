package result

import (
	"fmt"
	"os"
	"text/tabwriter"

	"webshell-detector/internal/detector"
)

// Printer 结果打印器
type Printer struct {
	showDetails bool
	colorize    bool
}

// NewPrinter 创建新的打印器
func NewPrinter(showDetails, colorize bool) *Printer {
	return &Printer{
		showDetails: showDetails,
		colorize:    colorize,
	}
}

// PrintResult 打印检测结果
func (p *Printer) PrintResult(result *detector.DetectionResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()

	// 打印分割线和标题
	fmt.Println("\n========== Webshell Detection Report ==========")

	// 基本信息
	fmt.Fprintf(w, "File Path:\t%s\n", result.FilePath)
	fmt.Fprintf(w, "Risk Level:\t%s\n", p.colorizeRiskLevel(string(result.RiskLevel)))
	fmt.Fprintf(w, "Is Webshell:\t%s\n", p.colorizeBoolean(result.IsWebshell))
	fmt.Fprintf(w, "Total Score:\t%.2f\n", result.TotalScore)
	fmt.Println()

	// 特征匹配结果
	fmt.Println("1. Feature Matching Analysis:")
	fmt.Fprintf(w, "   特征匹配结果Score:\t%.2f\n", result.FeatureScore)
	if len(result.MatchedFeatures) > 0 {
		fmt.Println("   Matched Features:")
		for _, feature := range result.MatchedFeatures {
			fmt.Fprintf(w, "   - %s\n", feature)
		}
	} else {
		fmt.Println("   No suspicious features detected")
	}
	fmt.Println()

	// 行为分析结果
	fmt.Println("2. Behavior Analysis:")
	fmt.Fprintf(w, "   行为分析结果 Score:\t%.2f\n", result.BehaviorScore)
	if len(result.Behaviors) > 0 {
		fmt.Println("   Detected Behaviors:")
		for _, behavior := range result.Behaviors {
			fmt.Fprintf(w, "   - %s\n", behavior)
		}
	} else {
		fmt.Println("   No suspicious behaviors detected")
	}
	fmt.Println()

	// 机器学习分析结果
	fmt.Println("3. Machine Learning Analysis:")
	fmt.Fprintf(w, "   机器学习分析得分Score:\t%.2f\n", result.MLScore)
	fmt.Println()

	// 打印分割线
	fmt.Println("============================================")
}

// colorizeRiskLevel 为风险等级添加颜色
func (p *Printer) colorizeRiskLevel(level string) string {
	if !p.colorize {
		return level
	}

	switch level {
	case "HIGH":
		return "\033[31m" + level + "\033[0m" // 红色
	case "MEDIUM":
		return "\033[33m" + level + "\033[0m" // 黄色
	case "LOW":
		return "\033[32m" + level + "\033[0m" // 绿色
	default:
		return "\033[34m" + level + "\033[0m" // 蓝色
	}
}

// colorizeBoolean 为布尔值添加颜色
func (p *Printer) colorizeBoolean(value bool) string {
	if !p.colorize {
		return fmt.Sprintf("%v", value)
	}

	if value {
		return "\033[31mYes\033[0m" // 红色
	}
	return "\033[32mNo\033[0m" // 绿色
}

// PrintSummary 打印扫描摘要
func (p *Printer) PrintSummary(results []*detector.DetectionResult) {
	var (
		totalFiles = len(results)
		webshells  = 0
		highRisk   = 0
		mediumRisk = 0
		lowRisk    = 0
		safe       = 0
	)

	// 统计结果
	for _, result := range results {
		if result.IsWebshell {
			webshells++
		}
		switch result.RiskLevel {
		case detector.RiskLevelHigh:
			highRisk++
		case detector.RiskLevelMedium:
			mediumRisk++
		case detector.RiskLevelLow:
			lowRisk++
		case detector.RiskLevelSafe:
			safe++
		}
	}

	// 创建格式化输出器
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintln(w, "\n=== Scan Summary ===")
	fmt.Fprintf(w, "Total Files Scanned:\t%d\n", totalFiles)
	fmt.Fprintf(w, "Webshells Detected:\t%d\n", webshells)
	fmt.Fprintf(w, "High Risk Files:\t%d\n", highRisk)
	fmt.Fprintf(w, "Medium Risk Files:\t%d\n", mediumRisk)
	fmt.Fprintf(w, "Low Risk Files:\t%d\n", lowRisk)
	fmt.Fprintf(w, "Safe Files:\t%d\n", safe)

	w.Flush()
}
