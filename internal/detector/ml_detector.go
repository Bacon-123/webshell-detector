/*
 * @Author: Mr.wpl
 * @Date: 2025-02-28 22:40:06
 * @Description:
 */
package detector

import (
	"context"
	"fmt"
	"strings"
)

// mlDetect 执行机器学习检测
func (d *Detector) mlDetect(ctx context.Context, content []byte) (float64, error) {
	// 提取特征
	features, err := d.extractFeatures(content)
	if err != nil {
		return 0, fmt.Errorf("failed to extract features: %v", err)
	}

	// 使用模型预测
	score, err := d.mlModel.Predict(features)
	if err != nil {
		return 0, fmt.Errorf("failed to predict: %v", err)
	}

	// 将预测概率转换为0-100的分数
	return score * 100, nil
}

// extractFeatures 提取文件特征
func (d *Detector) extractFeatures(content []byte) ([]float64, error) {
	fileStr := string(content)
	features := make([]float64, 5) // 只提取5个特征，与训练时保持一致

	// 1. 文件大小
	features[0] = float64(len(content))

	// 2. 危险函数数量
	dangerousFuncs := []string{"eval(", "system(", "exec(", "shell_exec(", "passthru("}
	count := 0
	for _, fun := range dangerousFuncs {
		count += strings.Count(fileStr, fun)
	}
	features[1] = float64(count)

	// 3. base64编码字符串的数量
	features[2] = float64(strings.Count(fileStr, "base64_decode"))

	// 4. 超全局变量使用数量
	superGlobals := []string{"$_POST", "$_GET", "$_REQUEST", "$_SERVER"}
	count = 0
	for _, sg := range superGlobals {
		count += strings.Count(fileStr, sg)
	}
	features[3] = float64(count)

	// 5. 文件操作函数数量
	fileOps := []string{"chmod(", "chown(", "fopen(", "file_put_contents("}
	count = 0
	for _, op := range fileOps {
		count += strings.Count(fileStr, op)
	}
	features[4] = float64(count)

	return features, nil
}
