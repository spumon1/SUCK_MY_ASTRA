package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

// 行为指纹的参照花名册 unified_bank.json 来自 sidecar 训练产物。
// 挑战要模型凭第一反应吐出 1..355 整数，不同模型各有自己的抓米手势。
// bank 装着 Hellinger、ordered-blocks 特征质心、去干扰基与校准系数，用来归因观测分布。
// 整本大册子嵌入插件，零外部依赖，出门不用再借字典。
//
//go:embed unified_bank.json
var unifiedBankJSON []byte

const (
	bankValueMin   = 1
	bankValueMax   = 355
	bankDimension  = bankValueMax - bankValueMin + 1 // 355
	bankAlpha      = 0.5
	bankMinNumbers = 80 // 单条至少凑够这些数字才收卷，半碗米不够认抓米手势
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

// loadBank 第一次有人查才解析嵌入 bank，随后缓存；厚账本翻一次就够，别每次重新装订。
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
