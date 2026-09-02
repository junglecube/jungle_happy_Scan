package plugin

import (
	"regexp"
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type MyBatisDynamicSQL struct{}

func (MyBatisDynamicSQL) Meta() model.PluginMeta {
	return StandardMeta("mybatis_dynamic_sql", "MyBatis 动态 SQL 片段注入", "仅探测排序列、字段名、表名和分组等高风险语义参数，使用不存在的 canary 标识符与反向恢复确认 ${} 直接拼接。", "active", true)
}

func (p MyBatisDynamicSQL) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	// Mode was a hidden payload-strength flag before V2.0. A legacy MyBatis
	// mode=deep payload must not silently execute when this plugin is selected
	// by normal mode; the canonical core canary already covers the same sink.
	payloads := make([]config.PayloadRule, 0, len(rule.Payloads))
	for _, payload := range rule.Payloads {
		if payload.Mode != "deep" {
			payloads = append(payloads, payload)
		}
	}
	patterns := compileDetectionPatterns(rule.Patterns)
	baselinePatterns := matchingPatternNames(patterns, ctx.Baselines)
	points := myBatisFragmentPoints(ctx.Points, rule.ParameterNames)
	total := len(points) * len(payloads) * 2
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	var findings []model.Finding
	for _, point := range points {
		for _, payload := range payloads {
			if payload.Kind != "fragment_break" {
				done += 2
				continue
			}
			token, value := myBatisProbeValue(point, payload)
			brokenOneRequest, err := ctx.Mutate(point, value)
			if err != nil {
				ctx.ResolveMutationFailed(2)
				done += 2
				continue
			}
			brokenTwoRequest, err := ctx.Mutate(point, value)
			if err != nil {
				ctx.ResolveMutationFailed(2)
				done += 2
				continue
			}
			requests := []*httpraw.Request{brokenOneRequest, brokenTwoRequest}
			cohort, reserveErr := ctx.ReserveCohort(len(requests))
			if reserveErr != nil {
				if reserveErr == ErrPluginBudgetExhausted {
					done += len(requests)
					ctx.Progress(meta.ID, min(done, total), max(total, 1))
					continue
				}
				return findings, reserveErr
			}
			responses := make([]model.Response, 0, 2)
			for _, request := range requests {
				response, sendErr := cohort.Send(request)
				if sendErr != nil {
					cohort.Close()
					return findings, sendErr
				}
				responses = append(responses, response)
				done++
				ctx.Progress(meta.ID, min(done, total), max(total, 1))
			}
			cohort.Close()
			first, second := responses[0], responses[1]
			repairOne, repairTwo := myBatisBaselineResponses(ctx)
			matchOne := myBatisNovelPatternRule(patterns, first.Body, token, baselinePatterns)
			matchTwo := myBatisNovelPatternRule(patterns, second.Body, token, baselinePatterns)
			if matchOne.name == "" || matchTwo.name != matchOne.name ||
				!strings.Contains(strings.ToLower(first.Text()), strings.ToLower(token)) ||
				!strings.Contains(strings.ToLower(second.Text()), strings.ToLower(token)) {
				continue
			}
			if hasNovelSQLPattern(patterns, repairOne.Body, baselinePatterns) ||
				hasNovelSQLPattern(patterns, repairTwo.Body, baselinePatterns) ||
				diff.Similarity(ctx.Baseline, repairOne, ctx.Config) < 0.86 ||
				diff.Similarity(ctx.Baseline, repairTwo, ctx.Config) < 0.86 ||
				diff.Similarity(first, second, ctx.Config) < 0.90 {
				continue
			}
			severityValue, confidenceValue := matchOne.severityConfidence()
			findings = append(findings, Finding(meta, "MyBatis 动态 SQL 片段可被客户端控制", severityValue, confidenceValue, point.Label(),
				"向高风险 SQL 片段参数加入唯一不存在标识符后，两次稳定进入数据库/ORM 并在错误中出现 canary；两条已采集基线均保持正常。该特征高度符合 MyBatis ${} 或存储过程动态 SQL 拼接，且不会为恢复步骤重复发送原始 POST。",
				"将值参数全部改为 #{}；排序列、方向、表名和字段列表无法绑定时，使用枚举到固定 SQL 片段的服务端白名单，禁止直接拼接请求参数。",
				[]model.Evidence{
					ctx.Evidence("第一轮动态片段 canary 进入数据库", brokenOneRequest, &first, map[string]any{"payload_rule": payload.Name, "match": limitedMatch(matchOne.text), "token": token}),
					ctx.Evidence("第一条已采集原始基线（未重复发送）", ctx.Request, &repairOne, map[string]any{"similarity": diff.Similarity(ctx.Baseline, repairOne, ctx.Config), "reused_baseline": true}),
					ctx.Evidence("第二条已采集原始基线（未重复发送）", ctx.Request, &repairTwo, map[string]any{"similarity": diff.Similarity(ctx.Baseline, repairTwo, ctx.Config), "reused_baseline": true}),
					ctx.Evidence("第二轮 canary 重复进入数据库", brokenTwoRequest, &second, map[string]any{"match": limitedMatch(matchTwo.text), "repeat_similarity": diff.Similarity(first, second, ctx.Config)}),
				}, "CWE-89", "MyBatis String Substitution"))
			break
		}
	}
	ctx.Progress(meta.ID, max(done, total), max(total, 1))
	return findings, nil
}

func myBatisBaselineResponses(ctx *Context) (model.Response, model.Response) {
	first, second := ctx.Baseline, ctx.Baseline
	if len(ctx.Baselines) > 0 {
		first = ctx.Baselines[0]
	}
	if len(ctx.Baselines) > 1 {
		second = ctx.Baselines[1]
	} else {
		second = first
	}
	return first, second
}

func myBatisProbeValue(point httpraw.InsertionPoint, payload config.PayloadRule) (string, string) {
	lower := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(point.Name))
	if strings.Contains(lower, "table") {
		token := "jhs_invalid_table_731"
		return token, point.Value + "," + token
	}
	token := defaultString(payload.Expected, "jhs_invalid_column_731")
	return token, expandPayload(payload.Payload, map[string]string{"value": point.Value, "token": token})
}

func myBatisPatternRule(patterns []compiledPattern, body []byte, token string) sqlPatternMatch {
	if match := firstPatternRule(patterns, body); match.name != "" {
		return match
	}
	quoted := regexp.QuoteMeta(token)
	pattern := regexp.MustCompile(`(?is)(?:` + quoted + `.{0,220}(?:unknown\s+column|doesn'?t\s+exist|does\s+not\s+exist|unknown\s+table|relation)|(?:unknown\s+column|table|relation).{0,220}` + quoted + `)`)
	if match := pattern.Find(body); len(match) > 0 {
		return sqlPatternMatch{name: "MyBatis 动态 SQL 标识符异常", text: string(match), severity: "high", confidence: "certain"}
	}
	return sqlPatternMatch{}
}

func myBatisNovelPatternRule(patterns []compiledPattern, body []byte, token string, baselinePatterns map[string]bool) sqlPatternMatch {
	best := sqlPatternMatch{}
	bestScore := -1
	for _, pattern := range patterns {
		if baselinePatterns[pattern.rule.Name] {
			continue
		}
		match := pattern.re.Find(body)
		if len(match) == 0 || !strings.Contains(strings.ToLower(string(match)), strings.ToLower(token)) {
			continue
		}
		candidate := sqlPatternMatch{
			name: pattern.rule.Name, text: string(match),
			severity: pattern.rule.Severity, confidence: pattern.rule.Confidence,
		}
		if score := sqlPatternValue(candidate); score > bestScore {
			best, bestScore = candidate, score
		}
	}
	if best.name != "" {
		return best
	}
	quoted := regexp.QuoteMeta(token)
	pattern := regexp.MustCompile(`(?is)(?:` + quoted + `.{0,220}(?:unknown\s+column|doesn'?t\s+exist|does\s+not\s+exist|unknown\s+table|relation)|(?:unknown\s+column|table|relation).{0,220}` + quoted + `)`)
	if match := pattern.Find(body); len(match) > 0 {
		return sqlPatternMatch{name: "MyBatis 动态 SQL 标识符异常", text: string(match), severity: "high", confidence: "certain"}
	}
	return sqlPatternMatch{}
}

func myBatisFragmentPoints(points []httpraw.InsertionPoint, names []string) []httpraw.InsertionPoint {
	if len(names) == 0 {
		names = []string{"sort", "order", "orderby", "order_by", "column", "field", "fields", "tablename", "table_name", "groupby", "group_by", "direction"}
	}
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		if normalized := normalizeSQLCandidateName(name); normalized != "" {
			allowed[normalized] = true
		}
	}
	var result []httpraw.InsertionPoint
	for _, point := range points {
		normalized := normalizeSQLCandidateName(point.Name)
		if allowed[normalized] || delimitedSQLCandidateSuffix(point.Name, allowed) ||
			normalizedSQLNameHasConfiguredSuffix(normalized, allowed) {
			result = append(result, point)
		}
	}
	return result
}
