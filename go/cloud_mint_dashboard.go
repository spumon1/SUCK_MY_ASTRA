package main

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const routeCloudDashboardStatus = "/codex-turn-state/cloud-status"
const cloudDashboardBuild = "cloud-mint-ui-20260926-fp2paths"
const cloudDashboardLogLimit = 80

type cloudDashboardLog struct {
	At              time.Time `json:"at"`
	Kind            string    `json:"kind"`
	Message         string    `json:"message"`
	requestSequence uint64
}

var cloudDashboardLogs = struct {
	sync.Mutex
	items []cloudDashboardLog
}{items: []cloudDashboardLog{}}

// 仅接收调用方已脱敏的结构化结果，日志缓存有界，不暴露在匿名资源路由。
func cloudRecordLog(kind, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	log.Printf(logPrefix+"%s · %s", kind, message)
	cloudDashboardLogs.Lock()
	defer cloudDashboardLogs.Unlock()
	cloudDashboardLogs.items = append(cloudDashboardLogs.items, cloudDashboardLog{At: time.Now(), Kind: kind, Message: message})
	if len(cloudDashboardLogs.items) > cloudDashboardLogLimit {
		cloudDashboardLogs.items = append([]cloudDashboardLog(nil), cloudDashboardLogs.items[len(cloudDashboardLogs.items)-cloudDashboardLogLimit:]...)
	}
}

// 请求头与后续模型声明更新同一条记录；淘汰后的旧请求不会被迟到事件重新插回。
func cloudUpsertRequestLog(sequence uint64, at time.Time, kind, message string, published bool) bool {
	cloudDashboardLogs.Lock()
	defer cloudDashboardLogs.Unlock()
	for i := range cloudDashboardLogs.items {
		item := &cloudDashboardLogs.items[i]
		if item.requestSequence != sequence {
			continue
		}
		if item.Message == message && item.Kind == kind {
			return false
		}
		item.Message, item.Kind = message, kind
		return true
	}
	if published {
		return false
	}
	cloudDashboardLogs.items = append(cloudDashboardLogs.items, cloudDashboardLog{
		At: at, Kind: kind, Message: message, requestSequence: sequence,
	})
	if len(cloudDashboardLogs.items) > cloudDashboardLogLimit {
		cloudDashboardLogs.items = append([]cloudDashboardLog(nil), cloudDashboardLogs.items[len(cloudDashboardLogs.items)-cloudDashboardLogLimit:]...)
	}
	return true
}

type cloudDashboardRow struct {
	Account     string `json:"account"`
	Model       string `json:"model"`
	Transport   string `json:"transport"`
	State       string `json:"state"`
	Gateway     string `json:"gateway"`
	Fingerprint string `json:"fingerprint"`
	Length      int    `json:"length"`
	SecondsLeft int64  `json:"seconds_left"`
}

func cloudWorkRow(work cloudMintWork) cloudDashboardRow {
	return cloudDashboardRow{Account: cloudFingerprint(work.creds.AuthID), Model: cloudSafeLabel(work.model), Transport: work.cfg.Transport, State: "minting", Gateway: cloudDisplayGateway(work.cfg.Gateway)}
}

func (s *cloudMintService) dashboardRows() []cloudDashboardRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := []cloudDashboardRow{}
	now := time.Now()
	for id, item := range s.cache {
		if _, busy := s.jobs[id]; busy || !item.until.After(now) {
			continue
		}
		row := item.row
		row.SecondsLeft = int64(item.until.Sub(now).Seconds())
		if item.err != nil {
			row.State = "cooldown"
		} else {
			row.State = "ready"
			row.Fingerprint = cloudFingerprint(item.entry.Ticket)
			row.Length = len(item.entry.Ticket)
		}
		rows = append(rows, row)
	}
	for _, job := range s.jobs {
		rows = append(rows, job.row)
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].Account+rows[i].Model+rows[i].Transport < rows[j].Account+rows[j].Model+rows[j].Transport
	})
	return rows
}

func handleCloudDashboardStatus() pluginapi.ManagementResponse {
	now := time.Now()
	state.mu.Lock()
	cfg := state.config
	pool := state.poolSnapshotLocked(now, cfg.ttl())
	state.mu.Unlock()
	fill := poolFillSnapshot()
	rows := currentCloudMintService().dashboardRows()
	cloudDashboardLogs.Lock()
	logs := append([]cloudDashboardLog{}, cloudDashboardLogs.items...)
	cloudDashboardLogs.Unlock()
	sort.SliceStable(logs, func(i, j int) bool { return logs[i].At.Before(logs[j].At) })
	// 主动探针可选账号:只给指纹(不暴露原始 auth_id/邮箱),面板回传指纹,由 handler 映射。
	mtAccounts := make([]string, 0, len(cfg.ProbeAccounts))
	for _, a := range cfg.ProbeAccounts {
		mtAccounts = append(mtAccounts, cloudFingerprint(a))
	}
	return jsonResponse(http.StatusOK, map[string]any{
		"plugin_id": currentCloudPluginID(), "build": cloudDashboardBuild, "enabled": cfg.CloudMint.Enabled, "role": cfg.Role, "dry_run": cfg.DryRun,
		"modeltrace_accounts": mtAccounts,
		"effective": map[string]any{"enabled": cfg.CloudMint.Enabled, "transport": cfg.CloudMint.Transport, "gateway": cfg.CloudMint.Gateway,
			"ticket_length": cfg.CloudMint.TicketLength, "ttl_seconds": cfg.CloudMint.TTLSeconds, "wait_ms": cfg.CloudMint.WaitMS, "timeout_ms": cfg.CloudMint.TimeoutMS,
			"pool_fill": cfg.CloudMint.PoolFill, "pool_fill_interval_ms": cfg.CloudMint.poolFillIntervalMS()},
		"rows": rows, "logs": logs, "worker_limit": cloudWorkersMax,
		"pool": map[string]any{
			"total": pool.Total, "usable": pool.Usable, "gateways": pool.Gateways, "rows": pool.Rows,
			"ttl_seconds": cfg.TTLSeconds, "fill": fill,
		},
	})
}
