package plugin

import (
	"strings"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type SQLOrderBy struct{}

func (SQLOrderBy) Meta() model.PluginMeta {
	return StandardMeta("sqli_order_by", "SQL ORDER BY 注入", "仅对排序参数执行 MySQL、PostgreSQL/GaussDB 条件错误和时间配对检测，不根据普通升降序变化报警。", "active", true)
}

func (p SQLOrderBy) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	points := namedSQLContextPoints(ctx.Points, rule.ParameterNames)
	conditionalPairs := pairPayloads(rule.Payloads, "conditional_control", "conditional_error")
	timePairs := pairPayloads(rule.Payloads, "time_control", "time_delay")
	total := 0
	for _, point := range points {
		total += (len(orderByPairsForPoint(conditionalPairs, point)) + len(orderByPairsForPoint(timePairs, point))) * 4
	}
	ctx.Progress(meta.ID, 0, max(total, 1))
	if len(points) == 0 || diff.BaselineStability(ctx.Baselines, ctx.Config) < 0.85 {
		ctx.Progress(meta.ID, max(total, 1), max(total, 1))
		return nil, nil
	}

	patterns, baselineErrors := sqlContextPatterns(ctx, meta.ID)
	baselineJitter := responseJitter(ctx.Baselines)
	done := 0
	var findings []model.Finding
	for _, point := range points {
		pointConditionalPairs := orderByPairsForPoint(conditionalPairs, point)
		pointTimePairs := orderByPairsForPoint(timePairs, point)
		original := strings.TrimSpace(point.Value)
		if original == "" {
			original = "1"
		}
		found := false
		for _, pair := range pointConditionalPairs {
			responses, requests, err := sendPairConfirmation(ctx, point, original, pair, func() {
				done++
				ctx.Progress(meta.ID, done, total)
			})
			if err != nil {
				return findings, err
			}
			if responses == nil || !validConditionalErrorResponses(ctx, responses...) {
				continue
			}
			controlOne, errorOne, errorTwo, controlTwo := responses[0], responses[1], responses[2], responses[3]
			controlOneSimilarity := diff.Similarity(ctx.Baseline, controlOne, ctx.Config)
			controlTwoSimilarity := diff.Similarity(ctx.Baseline, controlTwo, ctx.Config)
			errorOneSimilarity := diff.Similarity(ctx.Baseline, errorOne, ctx.Config)
			errorTwoSimilarity := diff.Similarity(ctx.Baseline, errorTwo, ctx.Config)
			controlsStable := diff.Similarity(controlOne, controlTwo, ctx.Config) >= 0.94
			errorsStable := diff.Similarity(errorOne, errorTwo, ctx.Config) >= 0.90
			controlsMatchBaseline := controlOne.StatusCode == ctx.Baseline.StatusCode &&
				controlTwo.StatusCode == ctx.Baseline.StatusCode &&
				min(controlOneSimilarity, controlTwoSimilarity) >= 0.90
			statusOracle := errorOne.StatusCode/100 != controlOne.StatusCode/100 &&
				errorTwo.StatusCode/100 != controlTwo.StatusCode/100
			contentOracle := min(controlOneSimilarity-errorOneSimilarity, controlTwoSimilarity-errorTwoSimilarity) >= 0.12
			matchOne, matchTwo := bestCommonPatternRules(patterns, errorOne.Body, errorTwo.Body, baselineErrors)
			controlClean := !hasNovelSQLPattern(patterns, controlOne.Body, baselineErrors) &&
				!hasNovelSQLPattern(patterns, controlTwo.Body, baselineErrors)
			explicitDatabaseError := matchOne.name != "" && matchOne.name == matchTwo.name &&
				!baselineErrors[matchOne.name] && controlClean
			stableWrappedError := errorOne.StatusCode >= 500 && errorTwo.StatusCode >= 500
			if !controlsStable || !errorsStable || !controlsMatchBaseline ||
				(!statusOracle && !contentOracle) || (!explicitDatabaseError && !stableWrappedError) {
				continue
			}
			severityValue, confidenceValue := model.SeverityHigh, model.ConfidenceFirm
			matchText, patternName := "", ""
			if explicitDatabaseError {
				severityValue, confidenceValue = matchOne.severityConfidence()
				confidenceValue = model.ConfidenceCertain
				matchText, patternName = matchOne.text, matchOne.name
			}
			findings = append(findings, Finding(meta, "SQL ORDER BY 条件错误注入", severityValue, confidenceValue, point.Label(),
				"排序参数的正常条件分支两次保持原排序并回到基线，异常条件分支两次稳定触发数据库错误。该检测不依赖 ASC/DESC 排序变化，也不提取数据库数据。",
				"排序字段和方向必须映射到服务端固定白名单，禁止把外部参数直接传入 MyBatis ${} 或拼接到 ORDER BY。",
				[]model.Evidence{
					ctx.Evidence("第一轮 ORDER BY 正常条件", requests[0], &controlOne, sqlPairMetrics(pair, 1, "control", "L4", map[string]any{"similarity": controlOneSimilarity, "payload_rule": pair.left.Name})),
					ctx.Evidence("第一轮 ORDER BY 异常条件", requests[1], &errorOne, sqlPairMetrics(pair, 2, "error", "L4", map[string]any{"similarity": errorOneSimilarity, "payload_rule": pair.right.Name, "pattern": patternName, "match": matchText})),
					ctx.Evidence("反向复核 ORDER BY 异常条件", requests[2], &errorTwo, sqlPairMetrics(pair, 3, "error", "L4", map[string]any{"similarity": errorTwoSimilarity, "pattern": patternName, "consistent": errorsStable})),
					ctx.Evidence("反向复核 ORDER BY 正常条件", requests[3], &controlTwo, sqlPairMetrics(pair, 4, "control", "L4", map[string]any{"similarity": controlTwoSimilarity, "consistent": controlsStable})),
				}, "OWASP WSTG-INPV-05"))
			found = true
			break
		}
		if found {
			done += len(pointTimePairs) * 4
			ctx.Progress(meta.ID, done, total)
			continue
		}
		for _, pair := range pointTimePairs {
			responses, requests, err := sendPairConfirmation(ctx, point, original, pair, func() {
				done++
				ctx.Progress(meta.ID, done, total)
			})
			if err != nil {
				return findings, err
			}
			if responses == nil || !validDifferentialResponses(ctx, responses) {
				continue
			}
			controlOne, delayedOne, delayedTwo, controlTwo := responses[0], responses[1], responses[2], responses[3]
			expected := expectedDelay(pair.right.Expected)
			margin := max(max(1200*time.Millisecond, expected*13/20), baselineJitter*4)
			deltaOne := delayedOne.Elapsed - controlOne.Elapsed
			deltaTwo := delayedTwo.Elapsed - controlTwo.Elapsed
			controlsStable := absDuration(controlOne.Elapsed-controlTwo.Elapsed) <= max(max(900*time.Millisecond, expected/2), baselineJitter*3)
			delaysStable := absDuration(delayedOne.Elapsed-delayedTwo.Elapsed) <= max(max(1200*time.Millisecond, expected*3/5), baselineJitter*4)
			if deltaOne < margin || deltaTwo < margin || !controlsStable || !delaysStable {
				continue
			}
			findings = append(findings, Finding(meta, "SQL ORDER BY 时间盲注", model.SeverityHigh, model.ConfidenceCertain, point.Label(),
				"排序参数的延迟条件在两轮反向顺序测试中均显著慢于零延迟对照，符合 ORDER BY 表达式被执行的特征。",
				"排序字段和方向必须使用服务端固定白名单，禁止动态拼接 ORDER BY 表达式。",
				[]model.Evidence{
					ctx.Evidence("第一轮 ORDER BY 零延迟对照", requests[0], &controlOne, sqlPairMetrics(pair, 1, "control", "L4", map[string]any{"elapsed_ms": controlOne.Elapsed.Milliseconds(), "payload_rule": pair.left.Name})),
					ctx.Evidence("第一轮 ORDER BY 延迟条件", requests[1], &delayedOne, sqlPairMetrics(pair, 2, "delay", "L4", map[string]any{"elapsed_ms": delayedOne.Elapsed.Milliseconds(), "delta_ms": deltaOne.Milliseconds(), "payload_rule": pair.right.Name})),
					ctx.Evidence("反向复核 ORDER BY 延迟条件", requests[2], &delayedTwo, sqlPairMetrics(pair, 3, "delay", "L4", map[string]any{"elapsed_ms": delayedTwo.Elapsed.Milliseconds(), "delta_ms": deltaTwo.Milliseconds()})),
					ctx.Evidence("反向复核 ORDER BY 零延迟对照", requests[3], &controlTwo, sqlPairMetrics(pair, 4, "control", "L4", map[string]any{"elapsed_ms": controlTwo.Elapsed.Milliseconds()})),
				}, "OWASP WSTG-INPV-05"))
			break
		}
	}
	return findings, nil
}

func orderByPairsForPoint(pairs []payloadPair, point httpraw.InsertionPoint) []payloadPair {
	context := "field"
	name := normalizeSQLCandidateName(point.Name)
	value := strings.ToLower(strings.TrimSpace(point.Value))
	if value == "asc" || value == "desc" || name == "direction" || strings.HasSuffix(name, "direction") ||
		name == "sortorder" || name == "orderdirection" {
		context = "direction"
	}
	result := make([]payloadPair, 0, len(pairs))
	for _, pair := range pairs {
		if strings.Contains(pair.group, "-"+context+"-") {
			result = append(result, pair)
		}
	}
	// Preserve administrator-authored legacy/custom pairs that do not declare
	// a field/direction context; only V2.3 built-ins are context-filtered.
	if len(result) == 0 {
		for _, pair := range pairs {
			if !strings.Contains(pair.group, "-field-") && !strings.Contains(pair.group, "-direction-") {
				result = append(result, pair)
			}
		}
	}
	return result
}

type SQLLimit struct{}

func (SQLLimit) Meta() model.PluginMeta {
	return StandardMeta("sqli_limit", "SQL LIMIT/OFFSET 注入", "仅对分页候选参数执行 MySQL 注释边界及 PostgreSQL/GaussDB 条件错误配对，不因正常分页数量变化报警。", "active", true)
}

func (p SQLLimit) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	points := namedSQLContextPoints(ctx.Points, rule.ParameterNames)
	pairs := pairPayloads(rule.Payloads, "error_break", "error_repair")
	total := len(points) * len(pairs) * 4
	ctx.Progress(meta.ID, 0, max(total, 1))
	if len(points) == 0 || diff.BaselineStability(ctx.Baselines, ctx.Config) < 0.85 {
		ctx.Progress(meta.ID, max(total, 1), max(total, 1))
		return nil, nil
	}
	patterns, baselineErrors := sqlContextPatterns(ctx, meta.ID)
	done := 0
	var findings []model.Finding
	for _, point := range points {
		original := strings.TrimSpace(point.Value)
		if original == "" {
			original = "1"
		}
		for _, pair := range pairs {
			responses, requests, err := sendPairConfirmation(ctx, point, original, pair, func() {
				done++
				ctx.Progress(meta.ID, done, total)
			})
			if err != nil {
				return findings, err
			}
			if responses == nil || !validConditionalErrorResponses(ctx, responses...) {
				continue
			}
			brokenOne, repairedOne, repairedTwo, brokenTwo := responses[0], responses[1], responses[2], responses[3]
			brokenOneSimilarity := diff.Similarity(ctx.Baseline, brokenOne, ctx.Config)
			brokenTwoSimilarity := diff.Similarity(ctx.Baseline, brokenTwo, ctx.Config)
			repairedOneSimilarity := diff.Similarity(ctx.Baseline, repairedOne, ctx.Config)
			repairedTwoSimilarity := diff.Similarity(ctx.Baseline, repairedTwo, ctx.Config)
			breaksStable := diff.Similarity(brokenOne, brokenTwo, ctx.Config) >= 0.92
			repairsStable := diff.Similarity(repairedOne, repairedTwo, ctx.Config) >= 0.94
			repairsMatchBaseline := repairedOne.StatusCode == ctx.Baseline.StatusCode &&
				repairedTwo.StatusCode == ctx.Baseline.StatusCode &&
				min(repairedOneSimilarity, repairedTwoSimilarity) >= 0.94
			statusOracle := brokenOne.StatusCode/100 != repairedOne.StatusCode/100 &&
				brokenTwo.StatusCode/100 != repairedTwo.StatusCode/100
			contentOracle := min(repairedOneSimilarity-brokenOneSimilarity, repairedTwoSimilarity-brokenTwoSimilarity) >= 0.08
			matchOne, matchTwo := bestCommonPatternRules(patterns, brokenOne.Body, brokenTwo.Body, baselineErrors)
			repairClean := !hasNovelSQLPattern(patterns, repairedOne.Body, baselineErrors) &&
				!hasNovelSQLPattern(patterns, repairedTwo.Body, baselineErrors)
			explicitDatabaseError := matchOne.name != "" && matchOne.name == matchTwo.name &&
				!baselineErrors[matchOne.name] && repairClean
			stableWrappedError := brokenOne.StatusCode >= 500 && brokenTwo.StatusCode >= 500
			if !breaksStable || !repairsStable || !repairsMatchBaseline ||
				(!statusOracle && !contentOracle) || (!explicitDatabaseError && !stableWrappedError) {
				continue
			}
			severityValue, confidenceValue := model.SeverityHigh, model.ConfidenceFirm
			matchText, patternName := "", ""
			if explicitDatabaseError {
				severityValue, confidenceValue = matchOne.severityConfidence()
				confidenceValue = model.ConfidenceCertain
				matchText, patternName = matchOne.text, matchOne.name
			}
			title := "SQL LIMIT/OFFSET 注释边界注入"
			description := "分页参数追加合法 MySQL 注释后两次恢复到基线，追加单引号再注释后两次稳定触发数据库错误。扫描器未把正常分页数量变化作为漏洞证据。"
			if strings.Contains(pair.group, "postgres") || strings.Contains(pair.group, "gauss") {
				title = "SQL LIMIT/OFFSET 条件错误注入"
				description = "分页参数的等价正常表达式两次保持原分页结果，异常表达式两次稳定触发 PostgreSQL/GaussDB 数据库错误；四次请求采用反向顺序确认。"
			}
			findings = append(findings, Finding(meta, title, severityValue, confidenceValue, point.Label(),
				description,
				"LIMIT和OFFSET必须转换为受控整数并使用参数绑定；禁止把分页文本直接拼接到SQL语句。",
				[]model.Evidence{
					ctx.Evidence("第一轮 LIMIT 引号破坏", requests[0], &brokenOne, sqlPairMetrics(pair, 1, "break", "L4", map[string]any{"similarity": brokenOneSimilarity, "payload_rule": pair.left.Name, "pattern": patternName, "match": matchText})),
					ctx.Evidence("第一轮 LIMIT 注释恢复", requests[1], &repairedOne, sqlPairMetrics(pair, 2, "repair", "L4", map[string]any{"similarity": repairedOneSimilarity, "payload_rule": pair.right.Name})),
					ctx.Evidence("反向复核 LIMIT 注释恢复", requests[2], &repairedTwo, sqlPairMetrics(pair, 3, "repair", "L4", map[string]any{"similarity": repairedTwoSimilarity, "consistent": repairsStable})),
					ctx.Evidence("反向复核 LIMIT 引号破坏", requests[3], &brokenTwo, sqlPairMetrics(pair, 4, "break", "L4", map[string]any{"similarity": brokenTwoSimilarity, "consistent": breaksStable, "pattern": patternName})),
				}, "OWASP WSTG-INPV-05"))
			break
		}
	}
	return findings, nil
}

func namedSQLContextPoints(points []httpraw.InsertionPoint, names []string) []httpraw.InsertionPoint {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		if normalized := normalizeSQLCandidateName(name); normalized != "" {
			allowed[normalized] = true
		}
	}
	var result []httpraw.InsertionPoint
	for _, point := range points {
		name := normalizeSQLCandidateName(point.Name)
		if allowed[name] || delimitedSQLCandidateSuffix(point.Name, allowed) ||
			normalizedSQLNameHasConfiguredSuffix(name, allowed) {
			result = append(result, point)
		}
	}
	return result
}

func delimitedSQLCandidateSuffix(name string, allowed map[string]bool) bool {
	parts := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(name)), func(character rune) bool {
		switch character {
		case '.', '[', ']', '_', '-':
			return true
		default:
			return false
		}
	})
	return len(parts) > 1 && allowed[normalizeSQLCandidateName(parts[len(parts)-1])]
}

func normalizeSQLCandidateName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var normalized strings.Builder
	normalized.Grow(len(name))
	for _, character := range name {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			normalized.WriteRune(character)
		}
	}
	return normalized.String()
}

func normalizedSQLNameHasConfiguredSuffix(name string, allowed map[string]bool) bool {
	for candidate := range allowed {
		if len(candidate) < 5 || len(name) <= len(candidate) || !strings.HasSuffix(name, candidate) {
			continue
		}
		prefix := strings.TrimSuffix(name, candidate)
		for _, container := range []string{"query", "search", "filter", "page", "pagination", "sort", "order", "request", "req", "dto", "params", "param"} {
			if strings.HasSuffix(prefix, container) {
				return true
			}
		}
	}
	return false
}

func hasNovelSQLPattern(patterns []compiledPattern, body []byte, baselinePatterns map[string]bool) bool {
	for _, pattern := range patterns {
		if baselinePatterns[pattern.rule.Name] {
			continue
		}
		if pattern.re.Match(body) {
			return true
		}
	}
	return false
}

func sqlContextPatterns(ctx *Context, pluginID string) ([]compiledPattern, map[string]bool) {
	rules := append([]config.DetectionRule(nil), ctx.Rule("sqli").Patterns...)
	rules = append(rules, ctx.Rule(pluginID).Patterns...)
	patterns := compileSQLDetectionPatternsWithConfidence(rules, ctx.Config.SQLiErrorPatterns, ctx.Config.SQLiErrorConfidence)
	baselineErrors := make(map[string]bool)
	for name := range matchingPatternNames(patterns, ctx.Baselines) {
		baselineErrors[name] = true
	}
	return patterns, baselineErrors
}
