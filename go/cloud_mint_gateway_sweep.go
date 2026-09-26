package main

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// 网关扫描:多轮经 FC 铸票 + modeltrace 指纹,按"票落在哪个网关"聚合每个网关的满血率,
// 找出稳定满血的 unified-N,供固定配置(MINT_GATEWAY / cloud_mint.gateway)。这是
// "FC 自动测满血网关"的功能:复用 FC modeltrace(path=fc),只是跑多轮再按网关归类。
const (
	gwSweepDefaultRounds = 6
	gwSweepMaxRounds     = 24
	gwSweepDefaultTurns  = 2
)

type gatewaySweepEntry struct {
	Gateway      string         `json:"gateway"`
	Rounds       int            `json:"rounds"`
	FullStrength int            `json:"full_strength"` // 指纹==请求模型 的轮数
	Predictions  map[string]int `json:"predictions"`   // 指纹判定模型 → 次数
}

type gatewaySweepReport struct {
	Model    string              `json:"model"`
	Rounds   int                 `json:"rounds"`
	Gateways []gatewaySweepEntry `json:"gateways"`
	Best     string              `json:"best"`       // 满血率最高的网关
	BestNote string              `json:"best_note"`  // 供直接固定的建议
}

func handleGatewaySweep(body []byte) pluginapi.ManagementResponse {
	var params struct {
		Model   string `json:"model"`
		Turns   int    `json:"turns"`
		Rounds  int    `json:"rounds"`
		Gateway string `json:"gateway"` // 可选:每轮定向该网关;留空=任意(靠出口落点,再按落点聚合)
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &params); err != nil {
			return managementError(http.StatusBadRequest, "请求体不是合法 JSON")
		}
	}
	model := params.Model
	if model == "" {
		model = modeltraceDefaultModel
	}
	turns := params.Turns
	if turns <= 0 {
		turns = gwSweepDefaultTurns
	}
	if turns > modeltraceMaxTurns {
		turns = modeltraceMaxTurns
	}
	rounds := params.Rounds
	if rounds <= 0 {
		rounds = gwSweepDefaultRounds
	}
	if rounds > gwSweepMaxRounds {
		rounds = gwSweepMaxRounds
	}

	state.mu.Lock()
	cfg := state.config
	state.mu.Unlock()

	perTurn := time.Duration(cfg.CloudMint.TimeoutMS) * time.Millisecond
	if perTurn <= 0 {
		perTurn = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), perTurn*time.Duration((turns+1)*rounds)+60*time.Second)
	defer cancel()

	agg := map[string]*gatewaySweepEntry{}
	for i := 0; i < rounds; i++ {
		if ctx.Err() != nil {
			break
		}
		rep, err := runModeltraceProbe(ctx, cfg, model, "fc", "", "", "fc", "", "", params.Gateway, turns)
		if err != nil {
			continue
		}
		gw := rep.MintGateway
		if gw == "" {
			gw = "(未知)"
		}
		e := agg[gw]
		if e == nil {
			e = &gatewaySweepEntry{Gateway: gw, Predictions: map[string]int{}}
			agg[gw] = e
		}
		e.Rounds++
		if rep.Fingerprint != nil {
			e.Predictions[rep.Fingerprint.Predicted]++
			if rep.Fingerprint.Match {
				e.FullStrength++
			}
		} else {
			e.Predictions["(无指纹)"]++
		}
	}

	report := gatewaySweepReport{Model: model, Rounds: rounds, Gateways: []gatewaySweepEntry{}}
	for _, e := range agg {
		report.Gateways = append(report.Gateways, *e)
	}
	// 满血率高、轮数多者优先。
	sort.SliceStable(report.Gateways, func(a, b int) bool {
		ga, gb := report.Gateways[a], report.Gateways[b]
		ra := float64(ga.FullStrength) / float64(max1(ga.Rounds))
		rb := float64(gb.FullStrength) / float64(max1(gb.Rounds))
		if ra != rb {
			return ra > rb
		}
		return ga.FullStrength > gb.FullStrength
	})
	for _, e := range report.Gateways {
		if e.FullStrength > 0 {
			report.Best = e.Gateway
			report.BestNote = "把 MINT_GATEWAY 与 cloud_mint.gateway 固定为 " + e.Gateway + ",并关闭 MINT_ROTATE_SID(固定住宅出口)"
			break
		}
	}
	if report.Best == "" {
		report.BestNote = "本次扫描未见任何网关满血(可能是出口/传输问题,不是网关选择问题)"
	}
	cloudRecordLog("gateway-sweep", "%s · %d 轮 · 满血网关=%s", cloudSafeLabel(model), rounds, cloudSafeLabel(report.Best))
	return jsonResponse(http.StatusOK, report)
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}
