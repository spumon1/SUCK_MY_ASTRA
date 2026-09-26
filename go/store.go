// 存储这间旧铺还管三样：原子写文件、观察桶键、旧桶 Cookie 的一次性迁入。
// 原来的模板仓库已撤柜：插件不再复用 X-Codex-Turn-State（见 FINDINGS.md），
// 可复用的是与账号无关的 __cflb/__oailb pair，由 route_cookies.go 管 route-cookies.json。
// 升级时从旧桶捡回仍有效的路由 Cookie，免得新店开张连一把椅子都没有。

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// atomicWrite 在同目录临时文件里写完再 rename，读者只见整盘菜，不见半截萝卜。
// os.CreateTemp 自带 0600，rename 保留权限，符合仓库的保密要求。
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, errTemp := os.CreateTemp(dir, ".tmp-*")
	if errTemp != nil {
		return errTemp
	}
	name := tmp.Name()
	// rename 成功后再清理也无害；失败分支更要收摊，不能留下临时文件满地摆摊。
	defer func() { _ = os.Remove(name) }()

	if _, errWrite := tmp.Write(data); errWrite != nil {
		_ = tmp.Close()
		return errWrite
	}
	if errSync := tmp.Sync(); errSync != nil {
		_ = tmp.Close()
		return errSync
	}
	if errClose := tmp.Close(); errClose != nil {
		return errClose
	}
	return os.Rename(name, path)
}

// bucketKey 用两边都不可能含有的 NUL 串起账号和模型，防止不同搭档撞成同一张桌号。
// 观察计数仍按桶记账，所以这把钥匙还没退休。
func bucketKey(authID, model string) string {
	return authID + "\x00" + model
}

// legacyRouteCookieEntries 从旧 <store_dir>/<auth_id>/<model>.json 的 route_cookies 捞回活 pair。
// 不再写旧记录，只在加载时迁入池；文件坏了或没了就跳过，不让一粒沙停掉整辆车。
func legacyRouteCookieEntries(dir string) []routeCookieEntry {
	authDirs, errRead := os.ReadDir(dir)
	if errRead != nil {
		return nil
	}
	var out []routeCookieEntry
	for _, authDir := range authDirs {
		if !authDir.IsDir() {
			continue
		}
		files, errAuth := os.ReadDir(filepath.Join(dir, authDir.Name()))
		if errAuth != nil {
			continue
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			data, errFile := os.ReadFile(filepath.Join(dir, authDir.Name(), file.Name()))
			if errFile != nil {
				continue
			}
			var legacy struct {
				RouteCookies       map[string]string `json:"route_cookies"`
				RouteCookiesAt     string            `json:"route_cookies_at"`
				RouteCookiesExpire string            `json:"route_cookies_expire"`
			}
			if errUnmarshal := json.Unmarshal(data, &legacy); errUnmarshal != nil {
				continue
			}
			if len(legacy.RouteCookies) == 0 || legacy.RouteCookiesAt == "" {
				continue
			}
			out = append(out, routeCookieEntry{
				Pairs:    legacy.RouteCookies,
				Gateway:  gatewayLabel(legacy.RouteCookies),
				SeenAt:   legacy.RouteCookiesAt,
				ExpireAt: legacy.RouteCookiesExpire,
			})
		}
	}
	return out
}

// bucketRelPath 替管理入口检查 auth_id/model：桶目录布局虽已退休，防越界门卫继续上班。
// 用于文件名或出站请求的值不能钻出目录；合法则回 <auth>/<model>.json，非法则指出哪半边闯祸。
func bucketRelPath(authID, model string) (string, error) {
	safe := func(s string) bool {
		if s == "" || len(s) > 256 {
			return false
		}
		return strings.IndexAny(s, `/\`+"\x00") < 0 && !strings.Contains(s, "..")
	}
	if !safe(authID) {
		return "", fmt.Errorf("unsafe auth_id %q", authID)
	}
	if !safe(model) {
		return "", fmt.Errorf("unsafe model %q", model)
	}
	return authID + "/" + model + ".json", nil
}
