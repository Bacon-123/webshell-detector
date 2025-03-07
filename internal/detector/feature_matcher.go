/*
 * @Author: Mr.wpl
 * @Date: 2025-02-28 22:39:38
 * @Description:
 */
package detector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hillu/go-yara/v4"
)

// FeatureMatchResult 特征匹配结果
type FeatureMatchResult struct {
	Score        float64
	Matches      []string
	YaraMatches  []string
	RegexMatches []string
}

// WebshellPatterns 定义常见webshell特征的正则表达式
var WebshellPatterns = []struct {
	Pattern string
	Score   float64
}{
	// 危险函数调用
	{
		Pattern: `\b(?:eval|system|exec|shell_exec|passthru|proc_open|popen|assert|create_function|include|require|file_put_contents|fwrite|fopen|unlink|rename|copy|symlink|base64_decode|gzinflate|str_rot13)\b\s*\(`,
		Score:   100,
	},
	// 动态函数执行
	{
		Pattern: `\bcall_user_func\s*\(\s*(?:'.*?'|".*?"|\$\w+)\s*[,\)]|\barray_map\s*\(|\bcreate_function\s*\(`,
		Score:   80,
	},
	// 编码或混淆绕过
	{
		Pattern: `\b(?:base64_decode|gzinflate|gzuncompress|str_rot13|convert_uudecode)\s*\(\s*(?:'[^']*'|"[^"]*")\s*\)`,
		Score:   100,
	},
	// 变量覆盖与输入接收
	{
		Pattern: `\b(?:\$\w+\s*=\s*[\$_](?:POST|GET|REQUEST|COOKIE|SERVER)\b|\$\w+\s*\(\s*\$\w+\s*\))`,
		Score:   80,
	},
	// 文件操作与后门特征
	{
		Pattern: `\b(?:file_put_contents|fwrite)\s*\(\s*'.*\.php'\s*,|\bchmod\s*\(\s*'.*'\s*,\s*0777\s*\)|\b@unlink\s*\(\s*__FILE__\s*\)`,
		Score:   80,
	},
}

// YaraConfig 配置Yara规则扫描
type YaraConfig struct {
	RulesDir    string   // 规则目录
	RuleTypes   []string // 要检测的规则类型,如 webshells,crypto 等
	MaxFileSize int64    // 最大扫描文件大小
}

// 初始化时预编译规则
// func (d *Detector) LoadYaraRules() error {
//
// }

// featureMatch 执行特征匹配检测
func (d *Detector) featureMatch(ctx context.Context, content []byte) (*FeatureMatchResult, error) {
	result := &FeatureMatchResult{
		Score:        0,
		Matches:      make([]string, 0),
		YaraMatches:  make([]string, 0),
		RegexMatches: make([]string, 0),
	}

	// 检查文件大小
	if int64(len(content)) > d.config.Detection.Yara.MaxFileSize {
		return nil, fmt.Errorf("file size exceeds maximum allowed size for YARA scanning")
	}

	// 执行正则匹配
	regexScore, regexMatches := d.matchRegexPatterns(content)
	result.RegexMatches = regexMatches
	result.Score += regexScore

	// 执行YARA规则匹配
	if d.config.Detection.Yara.Enabled {
		yaraScore, yaraMatches, err := d.matchYaraRules(content)
		if err != nil {
			return nil, fmt.Errorf("YARA matching failed: %v", err)
		}
		result.YaraMatches = yaraMatches
		result.Score += yaraScore
	}

	// 合并所有匹配结果
	result.Matches = append(result.RegexMatches, result.YaraMatches...)

	// 归一化分数
	if result.Score > 100 {
		result.Score = 100
	}

	return result, nil
}

// matchRegexPatterns 执行正则表达式匹配
func (d *Detector) matchRegexPatterns(content []byte) (float64, []string) {
	var score float64
	var matches []string
	fileStr := string(content)

	// 使用预定义的Webshell特征模式
	for _, pattern := range WebshellPatterns {
		re := regexp.MustCompile(pattern.Pattern)
		if re.MatchString(fileStr) {
			score += pattern.Score
			matches = append(matches, pattern.Pattern)
		}
	}

	return score, matches
}

// matchYaraRules 执行YARA规则匹配【每次扫描，都要加载规则，效率慢】
func (d *Detector) matchYaraRules(content []byte) (float64, []string, error) {
	var score float64
	var matches []string

	// 遍历指定的规则类型目录
	for _, ruleType := range d.config.Detection.Yara.RuleTypes {
		rulePath := filepath.Join(d.config.Detection.Yara.RulesDir, ruleType)

		// 递归扫描规则文件
		err := filepath.Walk(rulePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if !info.IsDir() && strings.HasSuffix(path, ".yar") {
				// 编译YARA规则
				compiler, err := yara.NewCompiler()
				if err != nil {
					return fmt.Errorf("failed to create YARA compiler: %v", err)
				}

				// 添加规则文件
				file, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("failed to open rule file %s: %v", path, err)
				}
				defer file.Close()
				if err := compiler.AddFile(file, ""); err != nil {
					return fmt.Errorf("failed to add rule file %s: %v", path, err)
				}

				// 获取规则
				rules, err := compiler.GetRules()
				if err != nil {
					return fmt.Errorf("failed to compile rules from %s: %v", path, err)
				}

				// 执行匹配
				var m yara.MatchRules
				timeout := 5 * time.Second // 设置超时时间
				err = rules.ScanMem(content, 0, timeout, &m)
				if err != nil {
					return fmt.Errorf("failed to scan with YARA: %v", err)
				}

				// 处理匹配结果
				for _, match := range m {
					// // 获取规则的分数
					// ruleScore := 10.0 // 默认分数
					// if meta, ok := match.Metas.(map[string]interface{}); ok {
					// 	if scoreVal, ok := meta["score"]; ok {
					// 		if scoreInt, ok := scoreVal.(int); ok {
					// 			ruleScore = float64(scoreInt)
					// 		}
					// 	}
					// }

					score += 50
					matches = append(matches, fmt.Sprintf("%s (%s)", match.Rule, strings.Join(match.Tags, ", ")))
				}
			}
			return nil
		})

		if err != nil {
			fmt.Printf("Warning: YARA scan failed for %s: %v\n", rulePath, err)
		}
	}
	if score > 100 {
		score = 100
	}
	return score, matches, nil
}
