package main

import (
	"errors"
	"math"
	"sort"
	"strconv"
)

// 把 sidecar modeltrace analyze.rs 的算盘搬来：模型输出整数序列，分类器据此认人。
// Hellinger 边际特征与 ordered-blocks 顺序特征分别投向 bank 质心打分，
// 加权合并后按校准 beta 做 softmax；不凭演员胸前名牌下结论。

// parseNumbers 捞文本中最长合法数字串，只留 [1,355]，含字母的分隔立即断段。
// 对应 analyze.rs::parse_numbers，数字队伍里混进字母就分桌，不硬凑一家。
func parseNumbers(text string) []int {
	var runs [][]int
	var current []int
	rs := []rune(text)
	i := 0
	for i < len(rs) {
		if rs[i] >= '0' && rs[i] <= '9' {
			start := i
			for i < len(rs) && rs[i] >= '0' && rs[i] <= '9' {
				i++
			}
			if v, err := strconv.Atoi(string(rs[start:i])); err == nil {
				if v >= bankValueMin && v <= bankValueMax {
					current = append(current, v)
				}
			}
		} else {
			hasLetter := false
			for i < len(rs) && !(rs[i] >= '0' && rs[i] <= '9') {
				if (rs[i] >= 'a' && rs[i] <= 'z') || (rs[i] >= 'A' && rs[i] <= 'Z') || rs[i] > 127 {
					// is_alphabetic：ASCII 字母或非 ASCII 字符按此处粗略等价规则处理，遇到就拆队。
					if unicodeIsLetter(rs[i]) {
						hasLetter = true
					}
				}
				i++
			}
			if hasLetter && len(current) > 0 {
				runs = append(runs, current)
				current = nil
			}
		}
	}
	if len(current) > 0 {
		runs = append(runs, current)
	}
	best := []int{}
	for _, r := range runs {
		if len(r) > len(best) {
			best = r
		}
	}
	return best
}

func unicodeIsLetter(r rune) bool {
	if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
		return true
	}
	// 非 ASCII 保守当字母，和 Rust char::is_alphabetic 在这里一样负责断段，不让陌生客混进数字席。
	return r > 127
}

func countNumbers(numbers []int) []float64 {
	counts := make([]float64, bankDimension)
	for _, n := range numbers {
		if n >= bankValueMin && n <= bankValueMax {
			counts[n-bankValueMin]++
		}
	}
	return counts
}

func meanOf(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := 0.0
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func standardize(v []float64) []float64 {
	m := meanOf(v)
	varSum := 0.0
	for _, x := range v {
		varSum += (x - m) * (x - m)
	}
	variance := varSum / float64(len(v))
	scale := math.Sqrt(variance)
	if scale < 1e-12 {
		scale = 1e-12
	}
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = (x - m) / scale
	}
	return out
}

func dotOf(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	s := 0.0
	for i := 0; i < n; i++ {
		s += a[i] * b[i]
	}
	return s
}

func normOf(v []float64) float64 { return math.Sqrt(dotOf(v, v)) }

func normalized(v []float64) []float64 {
	scale := normOf(v)
	if scale < 1e-12 {
		scale = 1e-12
	}
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = x / scale
	}
	return out
}

// subtractBasis 挨个减去基向量上的投影，用 Gram-Schmidt 去干扰，先掸灰再认脸。
func subtractBasis(values []float64, basis [][]float64) []float64 {
	out := make([]float64, len(values))
	copy(out, values)
	for _, vec := range basis {
		proj := dotOf(out, vec)
		n := len(out)
		if len(vec) < n {
			n = len(vec)
		}
		for i := 0; i < n; i++ {
			out[i] -= proj * vec[i]
		}
	}
	return out
}

func hellingerFeature(counts []float64) []float64 {
	total := 0.0
	for _, c := range counts {
		total += c
	}
	total += bankAlpha * float64(bankDimension)
	out := make([]float64, len(counts))
	for i, c := range counts {
		out[i] = math.Sqrt((c + bankAlpha) / total)
	}
	return out
}

func splitIntoFour(values []int) [][]int {
	base := len(values) / 4
	rem := len(values) % 4
	chunks := make([][]int, 0, 4)
	start := 0
	for i := 0; i < 4; i++ {
		size := base
		if i < rem {
			size = base + 1
		}
		chunks = append(chunks, values[start:start+size])
		start += size
	}
	return chunks
}

func orderedBlockFeature(numbers []int) []float64 {
	var pieces []float64
	for _, chunk := range splitIntoFour(numbers) {
		var bins [16]float64
		for i := range bins {
			bins[i] = 0.5
		}
		for _, val := range chunk {
			idx := int(float64(val-1) / 355.0 * 16.0)
			if idx > 15 {
				idx = 15
			}
			if idx < 0 {
				idx = 0
			}
			bins[idx]++
		}
		total := 0.0
		for _, b := range bins {
			total += b
		}
		for _, b := range bins {
			pieces = append(pieces, math.Sqrt(b/total))
		}
	}
	var lastDigits [10]float64
	for i := range lastDigits {
		lastDigits[i] = 0.5
	}
	for _, val := range numbers {
		d := val % 10
		if d < 0 {
			d += 10
		}
		lastDigits[d]++
	}
	lastTotal := 0.0
	for _, d := range lastDigits {
		lastTotal += d
	}
	for _, d := range lastDigits {
		pieces = append(pieces, math.Sqrt(d/lastTotal))
	}
	return pieces
}

func robustScoreCounts(counts []float64, bank *modeltraceBank) []float64 {
	art := &bank.Robust.Hellinger
	feat := hellingerFeature(counts)
	proj := make([]float64, len(feat))
	for i := range feat {
		proj[i] = (feat[i] - art.FeatureMean[i]) / art.FeatureScale[i]
	}
	proj = subtractBasis(proj, art.NuisanceBasis)
	proj = normalized(proj)
	scores := make([]float64, len(art.Centroids))
	for i, c := range art.Centroids {
		scores[i] = dotOf(proj, c)
	}
	return standardize(scores)
}

func orderedBlockScores(numbers []int, bank *modeltraceBank) []float64 {
	art := &bank.Robust.OrderedBlocks
	feat := orderedBlockFeature(numbers)
	stdFeat := make([]float64, len(feat))
	for i := range feat {
		stdFeat[i] = (feat[i] - art.FeatureMean[i]) / art.FeatureScale[i]
	}
	unit := normalized(stdFeat)

	envScores := make([][]float64, len(art.EnvironmentCentroids))
	for e, centroids := range art.EnvironmentCentroids {
		row := make([]float64, len(centroids))
		for i, c := range centroids {
			row[i] = dotOf(unit, c)
		}
		envScores[e] = row
	}

	modelCount := len(art.Centroids)
	rawTemplate := make([]float64, modelCount)
	for m := 0; m < modelCount; m++ {
		maxScore := -math.MaxFloat64
		for _, scores := range envScores {
			if m < len(scores) && scores[m] > maxScore {
				maxScore = scores[m]
			}
		}
		rawTemplate[m] = maxScore
	}
	template := standardize(rawTemplate)

	projected := normalized(subtractBasis(stdFeat, art.NuisanceBasis))
	rawNuisance := make([]float64, modelCount)
	for i, c := range art.Centroids {
		rawNuisance[i] = dotOf(projected, c)
	}
	nuisance := standardize(rawNuisance)

	combined := make([]float64, modelCount)
	for i := 0; i < modelCount; i++ {
		combined[i] = 0.5*template[i] + 0.5*nuisance[i]
	}
	return standardize(combined)
}

func robustScoreNumbers(numbers []int, bank *modeltraceBank) []float64 {
	counts := countNumbers(numbers)
	marginal := robustScoreCounts(counts, bank)
	weight := bank.Robust.OrderedBlocks.Weight
	if weight == 0 {
		return marginal
	}
	ordered := orderedBlockScores(numbers, bank)
	out := make([]float64, len(marginal))
	for i := range marginal {
		out[i] = (1.0-weight)*marginal[i] + weight*ordered[i]
	}
	return out
}

func softmax(values []float64) []float64 {
	maxVal := math.Inf(-1)
	for _, v := range values {
		if v > maxVal {
			maxVal = v
		}
	}
	exps := make([]float64, len(values))
	total := 0.0
	for i, v := range values {
		exps[i] = math.Exp(v - maxVal)
		total += exps[i]
	}
	out := make([]float64, len(values))
	for i := range exps {
		out[i] = exps[i] / total
	}
	return out
}

type modelAttribution struct {
	Model       string  `json:"model"`
	DisplayName string  `json:"display_name"`
	Family      string  `json:"family"`
	Probability float64 `json:"probability"`
	Score       float64 `json:"score"`
}

type attributionReport struct {
	PredictedModel  string             `json:"predicted_model"`
	DisplayName     string             `json:"display_name"`
	Confidence      float64            `json:"confidence"`
	Results         []modelAttribution `json:"results"`
	ValidOutputs    int                `json:"valid_outputs"`
	ParsedPerOutput []int              `json:"parsed_per_output"`
}

// analyzeOutputs 按若干输出文本给模型做行为归因，对应 analyze.rs::analyze_outputs，不看名牌看手艺。
func analyzeOutputs(texts []string, bank *modeltraceBank) (*attributionReport, error) {
	var validNumbers [][]int
	parsedCounts := make([]int, 0, len(texts))
	for _, txt := range texts {
		nums := parseNumbers(txt)
		parsedCounts = append(parsedCounts, len(nums))
		if len(nums) >= bankMinNumbers {
			validNumbers = append(validNumbers, nums)
		}
	}
	if len(validNumbers) == 0 {
		return nil, errors.New("没有有效输出(每条挑战需解析出至少 80 个数字)")
	}

	modelCount := len(bank.Models)
	allScores := make([][]float64, len(validNumbers))
	for i, nums := range validNumbers {
		allScores[i] = robustScoreNumbers(nums, bank)
	}
	combined := make([]float64, modelCount)
	for m := 0; m < modelCount; m++ {
		sum := 0.0
		for _, s := range allScores {
			sum += s[m]
		}
		combined[m] = sum / float64(len(validNumbers))
	}

	calKey := strconv.Itoa(min(len(validNumbers), 3))
	beta := 1.0
	if c, ok := bank.Calibration[calKey]; ok {
		beta = c.Beta
	}
	scaled := make([]float64, modelCount)
	for i := range combined {
		scaled[i] = beta * combined[i]
	}
	probs := softmax(scaled)

	results := make([]modelAttribution, modelCount)
	for i, m := range bank.Models {
		results[i] = modelAttribution{
			Model: m.ID, DisplayName: m.DisplayName, Family: m.Family,
			Probability: probs[i], Score: combined[i],
		}
	}
	sort.SliceStable(results, func(a, b int) bool { return results[a].Probability > results[b].Probability })

	top := results[0]
	return &attributionReport{
		PredictedModel:  top.Model,
		DisplayName:     top.DisplayName,
		Confidence:      top.Probability,
		Results:         results,
		ValidOutputs:    len(validNumbers),
		ParsedPerOutput: parsedCounts,
	}, nil
}
