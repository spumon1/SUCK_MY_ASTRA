package main

import "testing"

func TestModeltraceTargetResolvesFCWithoutEnabled(t *testing.T) {
	c := cloudMintConfig{FC: cloudFillSource{Enabled: false, URL: "https://fc.example/"}}
	target, err := modeltraceTarget(c, "fc", "")
	if err != nil || target.Name != "fc" || target.URL != "https://fc.example/" {
		t.Fatalf("即使未 enabled 也应解析 FC, 得到 %+v err=%v", target, err)
	}
}

func TestModeltraceTargetURLOverride(t *testing.T) {
	c := cloudMintConfig{FC: cloudFillSource{URL: "https://old/"}}
	target, err := modeltraceTarget(c, "fc", "https://new/")
	if err != nil || target.URL != "https://new/" {
		t.Fatalf("url 覆盖应生效, 得到 %+v err=%v", target, err)
	}
}

func TestModeltraceTargetMissingURL(t *testing.T) {
	if _, err := modeltraceTarget(cloudMintConfig{}, "fc", ""); err == nil {
		t.Fatal("无地址应报错")
	}
}

func TestModeltraceTargetUnknownSource(t *testing.T) {
	if _, err := modeltraceTarget(cloudMintConfig{}, "bogus", "https://x/"); err == nil {
		t.Fatal("未知源应报错")
	}
}

func TestCloudPairCookie(t *testing.T) {
	got := cloudPairCookie(map[string]string{"__oailb": "b", "__cflb": "a", "junk": "x"})
	if got != "__cflb=a; __oailb=b" {
		t.Fatalf("pair cookie=%q 应为 __cflb=a; __oailb=b", got)
	}
	if cloudPairCookie(map[string]string{}) != "" {
		t.Fatal("空 pair 应为空串")
	}
}
