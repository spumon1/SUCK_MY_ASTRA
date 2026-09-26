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

// 网关扫描复用 FC modeltrace(path=fc)，多轮铸票加行为指纹，按票落点统计各网关满血率。
// 为 MINT_GATEWAY / cloud_mint.gateway 找稳定的 unified-N，像选厨师先看多桌出菜，
// 不是看一盘好菜就封厨神；本质是多轮 FC 探测再按网关归账。
const (
	gwSweepDefaultRounds = 6
	gwSweepMaxRounds     = 24
	gwSweepDefaultTurns  = 2
)

type gatewaySweepEntry struct {
	Gateway      string         `json:"gateway"`
	Rounds       int            `json:"rounds"`
	FullStrength int            `json:"full_strength"` // 指纹等于请求模型的轮数，出菜手势与点单对上账
	Predictions  map[string]int `json:"predictions"`   // 指纹判定模型到次数的账本，不按胸牌数人头
}

type gatewaySweepReport struct {
	Model    string              `json:"model"`
	Rounds   int                 `json:"rounds"`
	Gateways []gatewaySweepEntry `json:"gateways"`
	Best     string              `json:"best"`      // 满血率最高的网关，本轮席上的头名
	BestNote string              `json:"best_note"` // 固定网关的建议，给配置抄门牌用
}

func handleGatewaySweep(body []byte) pluginapi.ManagementResponse {
	var params struct {
		Model   string `json:"model"`
		Turns   int    `json:"turns"`
		Rounds  int    `json:"rounds"`
		Gateway string `json:"gateway"` // 可选定向网关；空则任意落点再聚合，先看车停哪站再记账
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
	// 先排满血率，再看轮数；成绩好还得考得多，一次蒙对不能坐头席。
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
