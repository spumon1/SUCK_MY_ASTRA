package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

// 行为指纹的判定基准(unified_bank.json,由 sidecar 的训练产物移植而来)。挑战让
// 模型凭第一反应输出 1..355 的整数,其分布因模型而异;bank 存了每个模型在
// Hellinger 与 ordered-blocks 两个特征空间里的质心 + 去干扰基 + 校准系数,据此把
// 观测分布归因到具体模型。数据体量大,随插件一起嵌入,零外部依赖。
//
//go:embed unified_bank.json
var unifiedBankJSON []byte

const (
	bankValueMin   = 1
	bankValueMax   = 355
	bankDimension  = bankValueMax - bankValueMin + 1 // 355
	bankAlpha      = 0.5
	bankMinNumbers = 80 // 单条输出至少解析出这么多数字才算有效
)

type bankModel struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Family      string `json:"family"`
	FamilyName  string `json:"family_name"`
}

type hellingerArtifact struct {
	FeatureMean   []float64   `json:"feature_mean"`
	FeatureScale  []float64   `json:"feature_scale"`
	NuisanceBasis [][]float64 `json:"nuisance_basis"`
	Centroids     [][]float64 `json:"centroids"`
}

type orderedBlocksArtifact struct {
	Weight               float64       `json:"weight"`
	FeatureMean          []float64     `json:"feature_mean"`
	FeatureScale         []float64     `json:"feature_scale"`
	EnvironmentCentroids [][][]float64 `json:"environment_centroids"`
	NuisanceBasis        [][]float64   `json:"nuisance_basis"`
	Centroids            [][]float64   `json:"centroids"`
}

type bankRobust struct {
	Hellinger     hellingerArtifact     `json:"hellinger"`
	OrderedBlocks orderedBlocksArtifact `json:"ordered_blocks"`
}

type bankCalibration struct {
	Beta float64 `json:"beta"`
}

type modeltraceBank struct {
	Models      []bankModel                `json:"models"`
	Robust      bankRobust                 `json:"robust"`
	Calibration map[string]bankCalibration `json:"calibration"`
}

var (
	bankOnce sync.Once
	bankData *modeltraceBank
	bankErr  error
)

// loadBank 惰性解析并缓存嵌入的 bank。
func loadBank() (*modeltraceBank, error) {
	bankOnce.Do(func() {
		var b modeltraceBank
		if err := json.Unmarshal(unifiedBankJSON, &b); err != nil {
			bankErr = fmt.Errorf("解析 unified_bank.json 失败: %w", err)
			return
		}
		if len(b.Models) == 0 || len(b.Robust.Hellinger.Centroids) != len(b.Models) {
			bankErr = fmt.Errorf("bank 结构异常: models=%d hellinger_centroids=%d", len(b.Models), len(b.Robust.Hellinger.Centroids))
			return
		}
		bankData = &b
	})
	return bankData, bankErr
}
