package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// 挑战生成移植 sidecar modeltrace challenge.rs，算法源自 github.com/xqy2006/ModelTrace。
// 请模型凭第一反应给 292..332 个 1..355 整数，措辞随机变化来抵抗缓存和套模板。
// 不许工具、代码或等差数列替考：要采的是它抓数字的手势，不是计算器的工牌。
type modeltraceChallenge struct {
	ID            string
	ExpectedCount int
	Prompt        string
}

func cryptoRandomInt(max int) int {
	if max <= 1 {
		return 0
	}
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	val := binary.LittleEndian.Uint64(buf[:])
	return int(val % uint64(max))
}

func chooseStr(items []string) string {
	if len(items) == 0 {
		return ""
	}
	return items[cryptoRandomInt(len(items))]
}

func generateChallenges(count int) []modeltraceChallenge {
	if count == 0 {
		count = 3
	}
	openings := []string{
		"This is an independent numerical selection task",
		"Perform a rapid item-by-item selection record",
		"Execute an immediate first-reaction integer selection",
		"Generate a set of non-semantic integer selections",
		"Record a series of direct item choices",
	}
	actions := []string{"Choose", "Give", "Select", "Provide", "Pick"}
	endings := []string{
		"Occasional repetitions are allowed; once an item is written, do not look back to sort, deduplicate, or modify it.",
		"Accidental duplicates are valid; do not rearrange or revise previous numbers.",
		"Identical values may appear again; do not organize or rewrite prior entries during generation.",
		"Repeated values do not need to be removed; do not filter, reorder, or adjust them to form a pattern.",
		"Numbers require no special meaning; values already produced remain unchanged.",
	}
	separators := []string{
		"Separate numbers with commas or spaces.",
		"Use a single consistent separator such as commas or spaces.",
		"Numbers may be separated by commas, spaces, or newlines.",
		"Any clear and consistent separator between numbers is acceptable.",
	}

	available := make([]int, 0, 41)
	for n := 292; n <= 332; n++ {
		available = append(available, n)
	}
	challenges := make([]modeltraceChallenge, 0, count)
	for i := 0; i < count; i++ {
		if len(available) == 0 {
			for n := 292; n <= 332; n++ {
				available = append(available, n)
			}
		}
		idx := cryptoRandomInt(len(available))
		length := available[idx]
		available = append(available[:idx], available[idx+1:]...)

		prompt := fmt.Sprintf(
			"%s. %s %d integers between 1 and 355 (inclusive) based strictly on your immediate first reaction for each position. "+
				"Every position must be chosen independently; do not count upwards from 1, do not produce consecutive increasing or decreasing sequences, "+
				"and do not use arithmetic progressions, loops, repeating blocks, or any other regular patterns. "+
				"This task must be completed directly by the language model itself: do not call or rely on any tools, including Python, code interpreters, "+
				"calculators, search, APIs, or external random number generators; do not write or execute code. "+
				"%s %s "+
				"Output the numbers directly starting from the first value, without repeating the quantity, range, or task instructions.",
			chooseStr(openings), chooseStr(actions), length, chooseStr(endings), chooseStr(separators),
		)
		challenges = append(challenges, modeltraceChallenge{
			ID:            fmt.Sprintf("probe-%d-%d", i+1, cryptoRandomInt(1_000_000)),
			ExpectedCount: length,
			Prompt:        prompt,
		})
	}
	return challenges
}
