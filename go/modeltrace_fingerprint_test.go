package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseNumbersLongestValidRun(t *testing.T) {
	// 对应 analyze.rs 的 test_parse_numbers。
	got := parseNumbers("Here are the numbers: 1, 5, 23, 355, 999 (invalid), 42.")
	want := []int{1, 5, 23, 355}
	if len(got) != len(want) {
		t.Fatalf("parseNumbers=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseNumbers=%v want %v", got, want)
		}
	}
}

func TestBankLoads(t *testing.T) {
	bank, err := loadBank()
	if err != nil {
		t.Fatalf("loadBank: %v", err)
	}
	if len(bank.Models) == 0 {
		t.Fatal("bank 无模型")
	}
	if len(bank.Robust.Hellinger.Centroids) != len(bank.Models) {
		t.Fatalf("hellinger centroids=%d != models=%d", len(bank.Robust.Hellinger.Centroids), len(bank.Models))
	}
	found := false
	for _, m := range bank.Models {
		if m.ID == "gpt-5.6-terra" {
			found = true
		}
	}
	if !found {
		t.Fatal("bank 缺少 gpt-5.6-terra(与 sidecar bank 测试一致)")
	}
}

func TestAnalyzeSynthetic(t *testing.T) {
	// 对应 analyze.rs 的 test_analyze_synthetic:合成一段数字,应能归因、confidence>0。
	bank, err := loadBank()
	if err != nil {
		t.Fatalf("loadBank: %v", err)
	}
	var parts []string
	for i := 1; i <= 300; i++ {
		parts = append(parts, strconv.Itoa((i*7)%355+1))
	}
	txt := strings.Join(parts, ", ")
	rep, err := analyzeOutputs([]string{txt, txt}, bank)
	if err != nil {
		t.Fatalf("analyzeOutputs: %v", err)
	}
	if rep.PredictedModel == "" {
		t.Fatal("predicted_model 为空")
	}
	if rep.Confidence <= 0 {
		t.Fatalf("confidence=%v 应 >0", rep.Confidence)
	}
	if rep.ValidOutputs != 2 {
		t.Fatalf("valid_outputs=%d 应为 2", rep.ValidOutputs)
	}
}

func TestAnalyzeRejectsTooFewNumbers(t *testing.T) {
	bank, _ := loadBank()
	if _, err := analyzeOutputs([]string{"1, 2, 3"}, bank); err == nil {
		t.Fatal("数字太少应报错(<80)")
	}
}

func TestGenerateChallengesShape(t *testing.T) {
	chs := generateChallenges(3)
	if len(chs) != 3 {
		t.Fatalf("challenges=%d 应为 3", len(chs))
	}
	for _, c := range chs {
		if c.ExpectedCount < 292 || c.ExpectedCount > 332 {
			t.Fatalf("expected_count=%d 应在 292..332", c.ExpectedCount)
		}
		if !strings.Contains(c.Prompt, "integers between 1 and 355") {
			t.Fatal("prompt 缺少关键措辞")
		}
	}
}
