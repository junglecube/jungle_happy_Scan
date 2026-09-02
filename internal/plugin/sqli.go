package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type SQLInjection struct{}

type payloadPair struct {
	group string
	left  config.PayloadRule
	right config.PayloadRule
}

// sqlPairMetrics makes every evidence item self-describing. Consumers should
// not have to infer pairing or request order from translated summaries.
func sqlPairMetrics(pair payloadPair, sequence int, role, strength string, extra map[string]any) map[string]any {
	metrics := make(map[string]any, len(extra)+7)
	for key, value := range extra {
		metrics[key] = value
	}
	metrics["group"] = pair.group
	metrics["pair_order"] = "A-B-B-A"
	metrics["pair_sequence"] = sequence
	metrics["pair_role"] = role
	metrics["paired_confirmed"] = true
	metrics["repeat_confirmed"] = true
	metrics["evidence_strength"] = strength
	return metrics
}

type sqlScanProfile struct {
	errorPairs       bool
	booleanPairs     bool
	timePairs        bool
	selectOneBoolean bool
}

func (SQLInjection) Meta() model.PluginMeta {
	return StandardMeta("sqli", "SQL 注入", "针对 PostgreSQL、GaussDB、MySQL、JDBC/MyBatis 与 CALL/CallableStatement 存储过程执行错误恢复、重复布尔差分和时间对照检测，不提取业务数据。", "active", true)
}

func (p SQLInjection) Scan(ctx *Context) ([]model.Finding, error) {
	return scanSQLInjection(ctx, p.Meta(), sqlScanProfile{errorPairs: true, booleanPairs: true, selectOneBoolean: true})
}

func scanSQLInjection(ctx *Context, meta model.PluginMeta, profile sqlScanProfile) ([]model.Finding, error) {
	rule := ctx.Rule(meta.ID)
	payloads := payloadsForMode(rule, ctx.Mode)
	errorPairs := pairPayloads(payloads, "error_break", "error_repair")
	conditionalPairs := pairPayloads(payloads, "conditional_control", "conditional_error")
	booleanPairs := pairPayloads(payloads, "boolean_true", "boolean_false")
	timePairs := pairPayloads(payloads, "time_control", "time_delay")
	if !profile.errorPairs {
		errorPairs = nil
	}
	if !profile.booleanPairs {
		booleanPairs = nil
	}
	if !profile.timePairs {
		timePairs = nil
	}
	points := prioritizeSQLPoints(ctx.Points)
	// Boolean and timing checks are repeated in reverse order. Repetition makes
	// dynamic Spring APIs and transient network latency far less likely to alert.
	total := 0
	for _, point := range points {
		selectedBooleanPairs := booleanPairs
		if profile.selectOneBoolean {
			selectedBooleanPairs = normalSQLBooleanPair(booleanPairs, point)
		}
		total += len(errorPairs)*4 + len(conditionalPairs)*4 + len(selectedBooleanPairs)*4 + len(timePairs)*4
		if meta.ID == "sqli" && len(errorPairs) > 0 {
			// The quote gate is a cheap applicability probe. When it signals,
			// confirmation is a new, atomically reserved A-B-B-A cohort; the gate
			// response is deliberately not reused as half of that observation.
			total++
		}
	}
	done := 0
	ctx.Progress(meta.ID, done, max(total, 1))
	patterns := compileSQLDetectionPatternsWithConfidence(rule.Patterns, ctx.Config.SQLiErrorPatterns, ctx.Config.SQLiErrorConfidence)
	baselineErrors := make(map[string]bool)
	for name := range matchingPatternNames(patterns, ctx.Baselines) {
		baselineErrors[name] = true
	}
	baselineStability := diff.BaselineStability(ctx.Baselines, ctx.Config)
	baselineJitter := responseJitter(ctx.Baselines)
	var findings []model.Finding

	for _, point := range points {
		original := point.Value
		confirmedForPoint := false
		conditionalAccounted := false
		errorPairsProcessed := 0
		contextKind := classifySQLContext(point)
		pointErrorPairs := prioritizeSQLErrorPairs(errorPairs, contextKind)
		var pendingQuoteFinding *model.Finding
		quoteRecoveryGroups := make(map[string]bool)
		// The core scan starts with one quote applicability probe. It only prunes
		// the quote/error-recovery branch; context-selected Boolean and timing
		// oracles still run, so numeric parameters are not lost behind a string
		// syntax gate.
		if meta.ID == "sqli" && len(pointErrorPairs) > 0 {
			pair := pointErrorPairs[0]
			gateReq, mutationErr := ctx.Mutate(point, expandPayload(pair.left.Payload, map[string]string{"value": original}))
			if mutationErr != nil {
				selectedBooleanCount := len(booleanPairs)
				if profile.selectOneBoolean {
					selectedBooleanCount = len(normalSQLBooleanPair(booleanPairs, point))
				}
				failed := 1 + len(pointErrorPairs)*4 + len(conditionalPairs)*4 + selectedBooleanCount*4 + len(timePairs)*4
				ctx.ResolveMutationFailed(failed)
				done += failed
				ctx.Progress(meta.ID, done, total)
				continue
			}
			gateCohort, reserveErr := ctx.ReserveCohort(1)
			if reserveErr != nil {
				return findings, reserveErr
			}
			gateResult, sendErr := gateCohort.Send(gateReq)
			gateCohort.Close()
			if sendErr != nil {
				return findings, sendErr
			}
			done++
			ctx.Progress(meta.ID, done, total)
			if !sqlQuoteGateSignal(ctx, gateResult, patterns, baselineErrors, baselineStability) {
				// A clean quote only rules out this quote/error-recovery family.
				// It must not suppress numeric, Boolean, double-quote or timing
				// contexts, which may be injectable without surfacing a quote
				// syntax error.
				remaining := len(pointErrorPairs) * 4
				if remaining > 0 {
					done += remaining
					ctx.ResolveAdaptivePruned(remaining)
				}
				errorPairsProcessed = 0
				pointErrorPairs = nil
				done += len(conditionalPairs) * 4
				ctx.ResolveAdaptivePruned(len(conditionalPairs) * 4)
				conditionalAccounted = true
				ctx.Progress(meta.ID, done, total)
			}
		}
		for _, pair := range pointErrorPairs {
			errorPairsProcessed++
			responses, requests, err := sendPairConfirmation(ctx, point, original, pair, func() {
				done++
				ctx.Progress(meta.ID, done, total)
			})
			if err != nil {
				return findings, err
			}
			if responses == nil {
				done += 4
				ctx.Progress(meta.ID, done, total)
				continue
			}
			brokenOne, repairedOne, repairedTwo, brokenTwo := responses[0], responses[1], responses[2], responses[3]
			brokenOneSimilarity := diff.Similarity(ctx.Baseline, brokenOne, ctx.Config)
			brokenTwoSimilarity := diff.Similarity(ctx.Baseline, brokenTwo, ctx.Config)
			repairedOneSimilarity := diff.Similarity(ctx.Baseline, repairedOne, ctx.Config)
			repairedTwoSimilarity := diff.Similarity(ctx.Baseline, repairedTwo, ctx.Config)
			matchOne, matchTwo := bestCommonPatternRules(patterns, brokenOne.Body, brokenTwo.Body, baselineErrors)
			repairClean := !hasNovelSQLPattern(patterns, repairedOne.Body, baselineErrors) &&
				!hasNovelSQLPattern(patterns, repairedTwo.Body, baselineErrors)
			statusChanged := brokenOne.StatusCode/100 != ctx.Baseline.StatusCode/100 || brokenTwo.StatusCode/100 != ctx.Baseline.StatusCode/100
			if matchOne.name != "" && matchOne.name == matchTwo.name && !baselineErrors[matchOne.name] && repairClean &&
				repairedOneSimilarity >= 0.82 && repairedTwoSimilarity >= 0.82 &&
				(min(repairedOneSimilarity-brokenOneSimilarity, repairedTwoSimilarity-brokenTwoSimilarity) >= 0.12 || statusChanged) {
				severity, confidence := matchOne.severityConfidence()
				severity = model.SeverityHigh
				findings = append(findings, Finding(meta, "SQL 错误型注入", severity, confidence, point.Label(),
					"两次破坏 payload 均触发同类数据库/ORM 异常，两次同组恢复 payload 均回到稳定基线。反向复核可排除接口原有异常和瞬时故障。",
					"MyBatis 使用 #{} 参数绑定，禁止 ${} 拼接；动态表名/排序字段采用白名单。存储过程参数必须使用 CallableStatement 绑定变量，禁止拼接 CALL 字符串。",
					[]model.Evidence{
						ctx.Evidence("第一轮破坏 payload 触发数据库错误", requests[0], &brokenOne, sqlPairMetrics(pair, 1, "break", "L4", map[string]any{"match": matchOne.text, "pattern": matchOne.name, "similarity": brokenOneSimilarity, "payload_rule": pair.left.Name, "sql_context": contextKind})),
						ctx.Evidence("第一轮配对恢复 payload", requests[1], &repairedOne, sqlPairMetrics(pair, 2, "repair", "L4", map[string]any{"similarity": repairedOneSimilarity, "payload_rule": pair.right.Name})),
						ctx.Evidence("反向复核恢复 payload", requests[2], &repairedTwo, sqlPairMetrics(pair, 3, "repair", "L4", map[string]any{"similarity": repairedTwoSimilarity})),
						ctx.Evidence("反向复核破坏 payload", requests[3], &brokenTwo, sqlPairMetrics(pair, 4, "break", "L4", map[string]any{"match": matchTwo.text, "pattern": matchTwo.name, "similarity": brokenTwoSimilarity})),
					}, "OWASP WSTG-INPV-05"))
				confirmedForPoint = true
				break
			}

			// Some Java/MyBatis applications catch the database exception and return
			// only a business error, so no SQL/JDBC signature reaches the client. A
			// quote still gives us a strong paired oracle: the original value plus one
			// quote repeatedly breaks the response, while the same value plus two
			// quotes repeatedly returns to the stable baseline. Require four responses
			// in A-B-B-A order and a stable original baseline before reporting.
			// Repeated 5xx is allowed only on the broken pair because many exception
			// handlers hide SQL keywords; authentication failures and rate limits are
			// always excluded.
			brokenConsistent := diff.Similarity(brokenOne, brokenTwo, ctx.Config) >= 0.92
			repairConsistent := diff.Similarity(repairedOne, repairedTwo, ctx.Config) >= 0.94
			repairMatchesStatus := repairedOne.StatusCode == ctx.Baseline.StatusCode && repairedTwo.StatusCode == ctx.Baseline.StatusCode
			repairSimilarity := min(repairedOneSimilarity, repairedTwoSimilarity)
			brokenSimilarity := max(brokenOneSimilarity, brokenTwoSimilarity)
			exactRecovery := sqlEquivalentResponse(ctx.Baseline, repairedOne, ctx.Config) &&
				sqlEquivalentResponse(ctx.Baseline, repairedTwo, ctx.Config)
			exactRepeatedBreak := sqlEquivalentResponse(brokenOne, brokenTwo, ctx.Config) &&
				!sqlEquivalentResponse(ctx.Baseline, brokenOne, ctx.Config)
			strongGap := brokenSimilarity <= 0.90 && repairSimilarity-brokenSimilarity >= 0.06
			subtleExactGap := exactRecovery && exactRepeatedBreak && brokenSimilarity < 0.995
			businessRecovery := sqlBusinessOutcomeABBAConfigured(ctx.Config, ctx.Baseline, repairedOne, brokenOne, brokenTwo, repairedTwo)
			// The quote-concat-empty pair appends '||''||' instead of two
			// quotes. In PostgreSQL/GaussDB this closes the original literal,
			// concatenates an empty string and reopens it, so the business value
			// remains unchanged. Treat both quote groups as the same strict
			// A-B-B-A recovery oracle.
			recoveryThreshold := requiredSQLRecoverySimilarity(ctx.Baseline, baselineStability)
			quoteSuspicion := strings.HasPrefix(pair.group, "quote") && baselineStability >= 0.85 && repairClean &&
				validQuoteRecoveryResponses(ctx, brokenOne, repairedOne, repairedTwo, brokenTwo) && repairMatchesStatus &&
				((repairSimilarity >= recoveryThreshold && (strongGap || subtleExactGap)) || businessRecovery) &&
				brokenConsistent && repairConsistent
			if quoteSuspicion {
				quoteRecoveryGroups[pair.group] = true
				// Dialect-specific conditional probes are selected adaptively from
				// the break response. With no disclosed dialect the order is:
				// portable, PostgreSQL/GaussDB, then MySQL, and stops on the first
				// confirmed oracle. This bounded fallback avoids assuming that a
				// generic Java business error means PostgreSQL.
				if !conditionalAccounted {
					conditionalAccounted = true
					conditionalForPoint := selectSQLConditionalPairs(conditionalPairs, bestNovelPatternRule(patterns, brokenOne.Body, baselineErrors), bestNovelPatternRule(patterns, brokenTwo.Body, baselineErrors))
					if finding, confirmed, err := confirmSQLConditionalError(ctx, meta, point, original, conditionalForPoint, patterns, baselineErrors, func() {
						done++
						ctx.Progress(meta.ID, done, total)
					}); err != nil {
						return findings, err
					} else if confirmed {
						findings = append(findings, finding)
						confirmedForPoint = true
						remaining := (len(conditionalPairs) - len(conditionalForPoint)) * 4
						done += remaining
						ctx.ResolveAdaptivePruned(remaining)
						ctx.Progress(meta.ID, done, total)
						break
					}
					remaining := (len(conditionalPairs) - len(conditionalForPoint)) * 4
					done += remaining
					ctx.ResolveAdaptivePruned(remaining)
					ctx.Progress(meta.ID, done, total)
				}
				quoteFinding := Finding(meta, "疑似 SQL 字符串边界可控", model.SeverityHigh, model.ConfidenceFirm, point.Label(),
					"原参数追加单引号后，两次响应稳定偏离基线；同组等价恢复表达式两次恢复到稳定基线。该结果符合 SQL 字符串边界被破坏后恢复的特征，但数据库条件复核尚未成立，因此按疑似入口降级报告。",
					"MyBatis 使用 #{} 参数绑定，禁止 ${} 拼接；动态表名、列名和排序方向映射到固定白名单；存储过程通过 CallableStatement 绑定变量，禁止拼接 CALL SQL。",
					[]model.Evidence{
						ctx.Evidence("第一轮单引号破坏响应", requests[0], &brokenOne, sqlPairMetrics(pair, 1, "break", "L2", map[string]any{"similarity": brokenOneSimilarity, "payload_rule": pair.left.Name, "sql_context": contextKind, "exact_recovery": exactRecovery, "exact_repeated_break": exactRepeatedBreak, "paired_recovery": true, "evidence_level": "疑似"})),
						ctx.Evidence("第一轮双单引号恢复响应", requests[1], &repairedOne, sqlPairMetrics(pair, 2, "repair", "L2", map[string]any{"similarity": repairedOneSimilarity, "payload_rule": pair.right.Name})),
						ctx.Evidence("反向复核双单引号恢复响应", requests[2], &repairedTwo, sqlPairMetrics(pair, 3, "repair", "L2", map[string]any{"similarity": repairedTwoSimilarity, "consistent": repairConsistent})),
						ctx.Evidence("反向复核单引号破坏响应", requests[3], &brokenTwo, sqlPairMetrics(pair, 4, "break", "L2", map[string]any{"similarity": brokenTwoSimilarity, "consistent": brokenConsistent})),
					}, "OWASP WSTG-INPV-05")
				pendingQuoteFinding = &quoteFinding
				if len(quoteRecoveryGroups) >= 2 {
					break
				}
			}
		}
		if !confirmedForPoint && errorPairsProcessed < len(pointErrorPairs) {
			remaining := (len(pointErrorPairs) - errorPairsProcessed) * 4
			done += remaining
			ctx.ResolveAdaptivePruned(remaining)
			ctx.Progress(meta.ID, done, total)
		}
		if !confirmedForPoint && len(quoteRecoveryGroups) >= 2 && pendingQuoteFinding != nil {
			promoteSQLQuoteRecovery(pendingQuoteFinding, len(quoteRecoveryGroups))
			findings = append(findings, *pendingQuoteFinding)
			pendingQuoteFinding = nil
			confirmedForPoint = true
		}

		selectedBooleanPairs := booleanPairs
		if profile.selectOneBoolean {
			selectedBooleanPairs = normalSQLBooleanPair(booleanPairs, point)
		}
		if confirmedForPoint {
			conditionalRemaining := 0
			if !conditionalAccounted {
				conditionalRemaining = len(conditionalPairs) * 4
			}
			remaining := (len(pointErrorPairs)-errorPairsProcessed)*4 + conditionalRemaining + len(selectedBooleanPairs)*4 + len(timePairs)*4
			done += remaining
			ctx.ResolveAdaptivePruned(remaining)
			ctx.Progress(meta.ID, done, total)
			continue
		}
		if !conditionalAccounted {
			remaining := len(conditionalPairs) * 4
			done += remaining
			ctx.ResolveAdaptivePruned(remaining)
			ctx.Progress(meta.ID, done, total)
		}

		// Unstable baselines cannot support high-confidence content differentials.
		booleanPairsProcessed := 0
		if baselineStability >= 0.85 {
			for _, pair := range selectedBooleanPairs {
				booleanPairsProcessed++
				responses, requests, err := sendBooleanConfirmation(ctx, point, original, pair, func() {
					done++
					ctx.Progress(meta.ID, done, total)
				})
				if err != nil {
					return findings, err
				}
				if responses == nil {
					done += 4
					ctx.Progress(meta.ID, done, total)
					continue
				}
				trueOne, falseOne, falseTwo, trueTwo := responses[0], responses[1], responses[2], responses[3]
				if !validDifferentialResponses(ctx, responses) {
					continue
				}
				t1, f1 := diff.Similarity(ctx.Baseline, trueOne, ctx.Config), diff.Similarity(ctx.Baseline, falseOne, ctx.Config)
				t2, f2 := diff.Similarity(ctx.Baseline, trueTwo, ctx.Config), diff.Similarity(ctx.Baseline, falseTwo, ctx.Config)
				trueConsistent := diff.Similarity(trueOne, trueTwo, ctx.Config) >= 0.90
				falseConsistent := diff.Similarity(falseOne, falseTwo, ctx.Config) >= 0.90
				statusMatches := trueOne.StatusCode == ctx.Baseline.StatusCode && trueTwo.StatusCode == ctx.Baseline.StatusCode
				booleanOracle, exactOracle, businessOracle := sqlBooleanDifferential(
					ctx, baselineStability, trueOne, falseOne, falseTwo, trueTwo,
					t1, f1, f2, t2, trueConsistent, falseConsistent, statusMatches,
				)
				if booleanOracle {
					findings = append(findings, Finding(meta, "SQL 布尔盲注", model.SeverityHigh, model.ConfidenceCertain, point.Label(),
						"逻辑真响应两次稳定接近基线，逻辑假响应两次稳定偏离基线；第二轮采用反向发送顺序以降低缓存、抖动和业务动态数据造成的误报。",
						"使用预编译参数绑定；MyBatis 禁止 ${} 接收用户输入。无法绑定的列名、排序方向和存储过程名必须映射到固定白名单。",
						[]model.Evidence{
							ctx.Evidence("第一轮逻辑真条件", requests[0], &trueOne, sqlPairMetrics(pair, 1, "true", "L4", map[string]any{"similarity": t1, "payload_rule": pair.left.Name, "exact_oracle": exactOracle, "business_oracle": businessOracle, "baseline_stability": baselineStability})),
							ctx.Evidence("第一轮逻辑假条件", requests[1], &falseOne, sqlPairMetrics(pair, 2, "false", "L4", map[string]any{"similarity": f1, "payload_rule": pair.right.Name, "exact_oracle": exactOracle, "business_oracle": businessOracle})),
							ctx.Evidence("反向复核逻辑假条件", requests[2], &falseTwo, sqlPairMetrics(pair, 3, "false", "L4", map[string]any{"similarity": f2, "consistent": falseConsistent, "exact_oracle": exactOracle, "business_oracle": businessOracle})),
							ctx.Evidence("反向复核逻辑真条件", requests[3], &trueTwo, sqlPairMetrics(pair, 4, "true", "L4", map[string]any{"similarity": t2, "consistent": trueConsistent, "exact_oracle": exactOracle, "business_oracle": businessOracle})),
						}, "OWASP WSTG-INPV-05"))
					confirmedForPoint = true
					break
				}
			}
		} else {
			remaining := len(selectedBooleanPairs) * 4
			done += remaining
			ctx.ResolveAdaptivePruned(remaining)
			ctx.Progress(meta.ID, done, total)
		}
		if confirmedForPoint {
			remaining := (len(selectedBooleanPairs)-booleanPairsProcessed)*4 + len(timePairs)*4
			done += remaining
			ctx.ResolveAdaptivePruned(remaining)
			ctx.Progress(meta.ID, done, total)
			continue
		}

		timePairsProcessed := 0
		timeConfirmed := false
		for _, pair := range prioritizeSQLTimingPairs(timePairs, point) {
			timePairsProcessed++
			responses, requests, err := sendTimingConfirmation(ctx, point, original, pair, func() {
				done++
				ctx.Progress(meta.ID, done, total)
			})
			if err != nil {
				return findings, err
			}
			if responses == nil {
				done += 4
				ctx.Progress(meta.ID, done, total)
				continue
			}
			controlOne, delayedOne, delayedTwo, controlTwo := responses[0], responses[1], responses[2], responses[3]
			if !validDifferentialResponses(ctx, responses) {
				continue
			}
			expected := expectedDelay(pair.right.Expected)
			margin := max(max(1200*time.Millisecond, expected*13/20), baselineJitter*4)
			deltaOne := delayedOne.Elapsed - controlOne.Elapsed
			deltaTwo := delayedTwo.Elapsed - controlTwo.Elapsed
			controlsStable := absDuration(controlOne.Elapsed-controlTwo.Elapsed) <= max(max(900*time.Millisecond, expected/2), baselineJitter*3)
			delaysStable := absDuration(delayedOne.Elapsed-delayedTwo.Elapsed) <= max(max(1200*time.Millisecond, expected*3/5), baselineJitter*4)
			if deltaOne >= margin && deltaTwo >= margin && controlsStable && delaysStable {
				findings = append(findings, Finding(meta, "SQL 时间盲注", model.SeverityHigh, model.ConfidenceCertain, point.Label(),
					"数据库延迟 payload 在两轮反向顺序测试中均显著慢于同组零延迟对照，符合 PostgreSQL pg_sleep 或 MySQL SLEEP 的执行特征。",
					"参数全部使用绑定变量；限制数据库账号执行动态 SQL 的权限，并审计存储过程中的动态语句与字符串拼接。",
					[]model.Evidence{
						ctx.Evidence("第一轮零延迟对照", requests[0], &controlOne, sqlPairMetrics(pair, 1, "control", "L4", map[string]any{"elapsed_ms": controlOne.Elapsed.Milliseconds(), "payload_rule": pair.left.Name})),
						ctx.Evidence("第一轮数据库延迟", requests[1], &delayedOne, sqlPairMetrics(pair, 2, "delay", "L4", map[string]any{"elapsed_ms": delayedOne.Elapsed.Milliseconds(), "delta_ms": deltaOne.Milliseconds(), "baseline_jitter_ms": baselineJitter.Milliseconds(), "payload_rule": pair.right.Name})),
						ctx.Evidence("反向复核数据库延迟", requests[2], &delayedTwo, sqlPairMetrics(pair, 3, "delay", "L4", map[string]any{"elapsed_ms": delayedTwo.Elapsed.Milliseconds(), "delta_ms": deltaTwo.Milliseconds()})),
						ctx.Evidence("反向复核零延迟对照", requests[3], &controlTwo, sqlPairMetrics(pair, 4, "control", "L4", map[string]any{"elapsed_ms": controlTwo.Elapsed.Milliseconds()})),
					}, "OWASP WSTG-INPV-05"))
				timeConfirmed = true
				break
			}
		}
		if timeConfirmed {
			remaining := (len(timePairs) - timePairsProcessed) * 4
			done += remaining
			ctx.ResolveAdaptivePruned(remaining)
			ctx.Progress(meta.ID, done, total)
		}
		if !timeConfirmed && pendingQuoteFinding != nil {
			if len(quoteRecoveryGroups) >= 2 {
				promoteSQLQuoteRecovery(pendingQuoteFinding, len(quoteRecoveryGroups))
			}
			findings = append(findings, *pendingQuoteFinding)
		}
	}
	return findings, nil
}

func promoteSQLQuoteRecovery(finding *model.Finding, groups int) {
	finding.Title = "SQL 单引号破坏与多路径恢复差分"
	finding.Severity = model.SeverityHigh
	finding.Description = "两种独立 SQL 恢复表达式均通过 A-B-B-A 反向复核：破坏响应稳定偏离，恢复响应稳定回到基线。虽然条件错误/布尔/时间 Oracle 未成立，多路径恢复已显著降低普通字符校验导致误报的可能。"
	for index := range finding.Evidence {
		finding.Evidence[index].Strength = "L3"
		finding.Evidence[index].Metrics["evidence_strength"] = "L3"
		finding.Evidence[index].Metrics["evidence_level"] = "较确定"
		finding.Evidence[index].Metrics["independent_recovery_groups"] = groups
	}
}

func sqlQuoteGateSignal(ctx *Context, response model.Response, patterns []compiledPattern, baselineErrors map[string]bool, stability float64) bool {
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
		response.StatusCode == http.StatusNotAcceptable || response.StatusCode == http.StatusTooManyRequests ||
		diff.LikelyAuthDenied(response, ctx.Config) || stability < 0.75 {
		return false
	}
	match := bestNovelPatternRule(patterns, response.Body, baselineErrors)
	if match.name != "" {
		return true
	}
	similarity := diff.Similarity(ctx.Baseline, response, ctx.Config)
	statusChanged := response.StatusCode/100 != ctx.Baseline.StatusCode/100
	baselineLength := len(diff.Normalize(ctx.Baseline, ctx.Config))
	responseLength := len(diff.Normalize(response, ctx.Config))
	nearEmpty := baselineLength >= 200 && responseLength*3 < baselineLength
	return statusChanged || nearEmpty || similarity <= 0.88
}

func preferredSQLPair(pairs []payloadPair, group string) []payloadPair {
	for _, pair := range pairs {
		if pair.group == group {
			return []payloadPair{pair}
		}
	}
	if len(pairs) > 0 {
		return pairs[:1]
	}
	return nil
}

func normalSQLBooleanPair(pairs []payloadPair, point httpraw.InsertionPoint) []payloadPair {
	preferred := "and-string"
	switch classifySQLContext(point) {
	case "numeric":
		preferred = "numeric"
	case "like-string":
		preferred = "like-wrapped-string"
	}
	return preferredSQLPair(pairs, preferred)
}

// prioritizeSQLTimingPairs keeps the common quoted-query MySQL forms ahead of
// broad dialect fallbacks. This reaches the most likely oracle before a target
// WAF or rate limiter is primed by unrelated timing syntax.
func prioritizeSQLTimingPairs(pairs []payloadPair, point httpraw.InsertionPoint) []payloadPair {
	preferred := []string{}
	switch classifySQLContext(point) {
	case "like-string", "string":
		preferred = []string{
			"mysql-sleep-and-select-exact-replace",
			"mysql-sleep-and-select-template-close",
			"mysql-sleep-string",
			"mysql-sleep-or-select-string",
		}
	default:
		preferred = []string{"mysql-sleep-and", "postgres-pg-sleep-and", "gaussdb-pg-sleep-and"}
	}
	result := make([]payloadPair, 0, len(pairs))
	used := make(map[int]bool, len(pairs))
	for _, group := range preferred {
		for index, pair := range pairs {
			if pair.group == group {
				result = append(result, pair)
				used[index] = true
			}
		}
	}
	for index, pair := range pairs {
		if !used[index] {
			result = append(result, pair)
		}
	}
	return result
}

func prioritizeSQLPoints(points []httpraw.InsertionPoint) []httpraw.InsertionPoint {
	result := make([]httpraw.InsertionPoint, 0, len(points))
	for _, point := range points {
		// SQL injection checks are limited to request parameters, not ambient
		// Cookie or header values.
		if point.Location == "cookie" || point.Location == "header" {
			continue
		}
		result = append(result, point)
	}
	sort.SliceStable(result, func(left, right int) bool {
		return sqlPointPriority(result[left]) > sqlPointPriority(result[right])
	})
	return result
}

func sqlPointPriority(point httpraw.InsertionPoint) int {
	score := 0
	switch point.Location {
	case "query", "json", "graphql_variable", "form":
		score += 40
	case "nested_json", "nested_xml", "base64_json", "base64_xml":
		score += 36
	case "multipart":
		score += 32
	case "path":
		score += 22
	case "cookie":
		score += 8
	case "header":
		score += 4
	}
	name := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(point.Name))
	for _, marker := range []string{"id", "name", "app", "query", "search", "filter", "where", "date", "time", "code", "account", "sort", "order", "limit", "offset", "page", "size"} {
		if name == marker || strings.HasSuffix(name, marker) {
			score += 25
			break
		}
	}
	for _, marker := range []string{"token", "session", "authorization", "csrf", "nonce", "signature", "sign"} {
		if strings.Contains(name, marker) {
			score -= 35
			break
		}
	}
	switch classifySQLContext(point) {
	case "numeric", "string", "date-string", "like-string":
		score += 12
	case "order-by", "limit-offset":
		score += 18
	case "header-path":
		score -= 8
	}
	return score
}

func classifySQLContext(point httpraw.InsertionPoint) string {
	name := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(point.Name))
	for _, marker := range []string{"orderby", "sortby", "sortfield", "sortcolumn", "orderfield", "ordercolumn", "direction"} {
		if name == marker || strings.HasSuffix(name, marker) {
			return "order-by"
		}
	}
	for _, marker := range []string{"limit", "offset", "pagesize", "pageno", "startrow", "rowcount"} {
		if name == marker || strings.HasSuffix(name, marker) {
			return "limit-offset"
		}
	}
	if point.Location == "header" || point.Location == "path" || point.Location == "cookie" {
		return "header-path"
	}
	value := strings.TrimSpace(point.Value)
	if regexp.MustCompile(`^\d{4}[-/]?\d{2}[-/]?\d{2}(?:[T ][0-9:.+-]+)?$`).MatchString(value) {
		return "date-string"
	}
	for _, marker := range []string{"query", "search", "keyword", "keywords", "filter", "name", "username", "user", "title", "content"} {
		if name == marker || strings.HasSuffix(name, marker) {
			return "like-string"
		}
	}
	if point.ValueType == "number" || sqlNumericLiteral(value) {
		return "numeric"
	}
	return "string"
}

var sqlNumberLiteralPattern = regexp.MustCompile(`^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$`)

func sqlNumericLiteral(value string) bool {
	return sqlNumberLiteralPattern.MatchString(strings.TrimSpace(value))
}

func prioritizeSQLErrorPairs(pairs []payloadPair, contextKind string) []payloadPair {
	result := append([]payloadPair(nil), pairs...)
	score := func(pair payloadPair) int {
		value := 0
		switch contextKind {
		case "string", "date-string", "like-string":
			if pair.group == "quote" {
				value += 30
			}
			if pair.group == "quote-concat-empty" {
				value += 20
			}
		case "numeric", "limit-offset", "order-by":
			if pair.group == "quote" {
				value += 30
			}
		case "header-path":
			if pair.group == "quote" {
				value += 20
			}
		}
		if strings.Contains(pair.group, "double-quote") {
			value -= 5
		}
		return value
	}
	sort.SliceStable(result, func(left, right int) bool { return score(result[left]) > score(result[right]) })
	return result
}

func selectSQLConditionalPairs(pairs []payloadPair, matches ...sqlPatternMatch) []payloadPair {
	dialect := ""
	for _, match := range matches {
		hint := strings.ToLower(match.name + " " + match.text)
		if strings.Contains(hint, "mysql") {
			dialect = "mysql"
			break
		}
		if strings.Contains(hint, "gauss") || strings.Contains(hint, "postgres") || strings.Contains(hint, "psql") {
			dialect = "postgres"
		}
	}
	if dialect != "" {
		preferredPrefix := dialect + "-"
		for _, pair := range pairs {
			if strings.HasPrefix(pair.group, preferredPrefix) {
				return []payloadPair{pair}
			}
		}
	}

	// No database signature was disclosed. Keep the fallback finite and
	// deterministic, but do not silently assume PostgreSQL merely because a
	// Spring/MyBatis handler returned a generic business error.
	result := make([]payloadPair, 0, 3)
	for _, wanted := range []string{"portable-", "postgres-", "mysql-"} {
		for _, pair := range pairs {
			if strings.HasPrefix(pair.group, wanted) {
				result = append(result, pair)
				break
			}
		}
	}
	if len(result) > 0 {
		return result
	}
	if len(pairs) > 0 {
		return pairs[:1]
	}
	return nil
}

func sendBooleanConfirmation(ctx *Context, point httpraw.InsertionPoint, original string, pair payloadPair, progress func()) ([]model.Response, []*httpraw.Request, error) {
	return sendPairConfirmation(ctx, point, original, pair, progress)
}

func sendTimingConfirmation(ctx *Context, point httpraw.InsertionPoint, original string, pair payloadPair, progress func()) ([]model.Response, []*httpraw.Request, error) {
	return sendPairConfirmation(ctx, point, original, pair, progress)
}

func confirmSQLConditionalError(
	ctx *Context,
	meta model.PluginMeta,
	point httpraw.InsertionPoint,
	original string,
	pairs []payloadPair,
	patterns []compiledPattern,
	baselineErrors map[string]bool,
	progress func(),
) (model.Finding, bool, error) {
	for pairIndex, pair := range pairs {
		responses, requests, err := sendPairConfirmation(ctx, point, original, pair, progress)
		if err != nil {
			return model.Finding{}, false, err
		}
		if responses == nil {
			for range 4 {
				progress()
			}
			continue
		}
		controlOne, errorOne, errorTwo, controlTwo := responses[0], responses[1], responses[2], responses[3]
		if !validConditionalErrorResponses(ctx, controlOne, errorOne, errorTwo, controlTwo) {
			continue
		}
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
		businessOutcomeOracle := sqlBusinessOutcomeABBAConfigured(ctx.Config, ctx.Baseline, controlOne, errorOne, errorTwo, controlTwo)
		matchOne, matchTwo := bestCommonPatternRules(patterns, errorOne.Body, errorTwo.Body, baselineErrors)
		controlClean := !hasNovelSQLPattern(patterns, controlOne.Body, baselineErrors) &&
			!hasNovelSQLPattern(patterns, controlTwo.Body, baselineErrors)
		explicitDatabaseError := matchOne.name != "" && matchOne.name == matchTwo.name &&
			!baselineErrors[matchOne.name] && controlClean
		controlsMatchBaseline = controlsMatchBaseline || businessOutcomeOracle
		if !controlsStable || !errorsStable || !controlsMatchBaseline || (!statusOracle && !contentOracle && !businessOutcomeOracle) {
			continue
		}
		if !explicitDatabaseError && !(errorOne.StatusCode >= 500 && errorTwo.StatusCode >= 500) && !businessOutcomeOracle {
			continue
		}
		severity, confidence := model.SeverityHigh, model.ConfidenceFirm
		matchText, patternName := "", ""
		if explicitDatabaseError {
			severity, confidence = matchOne.severityConfidence()
			matchText, patternName = matchOne.text, matchOne.name
		}
		severity = model.SeverityHigh
		databaseFamily := "PostgreSQL/GaussDB"
		if strings.HasPrefix(pair.group, "mysql-") {
			databaseFamily = "MySQL"
		} else if strings.HasPrefix(pair.group, "portable-") {
			databaseFamily = "MySQL/PostgreSQL/GaussDB"
		}
		finding := Finding(meta, "SQL 条件错误差分注入", severity, confidence, point.Label(),
			"在单引号破坏/恢复信号之后，扫描器使用只改变条件谓词的 "+databaseFamily+" 配对表达式进行 A-B-B-A 复核。正常分支两次稳定回到基线，错误分支两次稳定触发不同响应；未提取数据库或业务数据。",
			"所有查询及存储过程参数使用绑定变量；MyBatis 禁止将外部输入传入 ${}。动态列名、排序方向和过程名必须映射到固定白名单。",
			[]model.Evidence{
				ctx.Evidence("第一轮条件正常分支", requests[0], &controlOne, sqlPairMetrics(pair, 1, "control", "L4", map[string]any{"similarity": controlOneSimilarity, "payload_rule": pair.left.Name, "database_family": databaseFamily})),
				ctx.Evidence("第一轮条件错误分支", requests[1], &errorOne, sqlPairMetrics(pair, 2, "error", "L4", map[string]any{"similarity": errorOneSimilarity, "payload_rule": pair.right.Name, "pattern": patternName, "match": matchText})),
				ctx.Evidence("反向复核条件错误分支", requests[2], &errorTwo, sqlPairMetrics(pair, 3, "error", "L4", map[string]any{"similarity": errorTwoSimilarity, "consistent": errorsStable, "pattern": patternName})),
				ctx.Evidence("反向复核条件正常分支", requests[3], &controlTwo, sqlPairMetrics(pair, 4, "control", "L4", map[string]any{"similarity": controlTwoSimilarity, "consistent": controlsStable})),
			}, "OWASP WSTG-INPV-05")
		remaining := (len(pairs) - pairIndex - 1) * 4
		ctx.ResolveAdaptivePruned(remaining)
		for range remaining {
			progress()
		}
		return finding, true, nil
	}
	return model.Finding{}, false, nil
}

// sqlBusinessOutcomeABBA recognizes a stable application-level outcome oracle.
// It is only used after the strict quote break/repair gate, so a pair such as
// code=0, code=-3, code=-3, code=0 can confirm a wrapped SQL error without
// requiring the application to expose a JDBC exception or HTTP 5xx status.
func sqlBusinessOutcomeABBA(baseline, controlOne, errorOne, errorTwo, controlTwo model.Response) bool {
	baselineOutcomes := sqlBusinessOutcomes(baseline)
	controlOneOutcomes := sqlBusinessOutcomes(controlOne)
	controlTwoOutcomes := sqlBusinessOutcomes(controlTwo)
	errorOneOutcomes := sqlBusinessOutcomes(errorOne)
	errorTwoOutcomes := sqlBusinessOutcomes(errorTwo)
	for path, baselineOutcome := range baselineOutcomes {
		controlOneOutcome, controlOneOK := controlOneOutcomes[path]
		controlTwoOutcome, controlTwoOK := controlTwoOutcomes[path]
		errorOneOutcome, errorOneOK := errorOneOutcomes[path]
		errorTwoOutcome, errorTwoOK := errorTwoOutcomes[path]
		if controlOneOK && controlTwoOK && errorOneOK && errorTwoOK &&
			controlOneOutcome == baselineOutcome && controlTwoOutcome == baselineOutcome &&
			errorOneOutcome == errorTwoOutcome && errorOneOutcome != baselineOutcome {
			return true
		}
	}
	return false
}

func sqlBusinessOutcomeABBAConfigured(cfg config.Config, baseline, controlOne, errorOne, errorTwo, controlTwo model.Response) bool {
	if sqlBusinessOutcomeABBA(baseline, controlOne, errorOne, errorTwo, controlTwo) {
		return true
	}
	baselineOutcome, baselineOK := sqlConfiguredOutcome(baseline, cfg)
	controlOneOutcome, controlOneOK := sqlConfiguredOutcome(controlOne, cfg)
	controlTwoOutcome, controlTwoOK := sqlConfiguredOutcome(controlTwo, cfg)
	errorOneOutcome, errorOneOK := sqlConfiguredOutcome(errorOne, cfg)
	errorTwoOutcome, errorTwoOK := sqlConfiguredOutcome(errorTwo, cfg)
	return baselineOK && controlOneOK && controlTwoOK && errorOneOK && errorTwoOK &&
		controlOneOutcome == baselineOutcome && controlTwoOutcome == baselineOutcome &&
		errorOneOutcome == errorTwoOutcome && errorOneOutcome != baselineOutcome
}

func sqlConfiguredOutcome(response model.Response, cfg config.Config) (string, bool) {
	body := response.Body
	patterns := append(append([]string(nil), cfg.SuccessPatterns...), cfg.DeniedPatterns...)
	if len(patterns) == 0 {
		return "", false
	}
	var matched []string
	for index, pattern := range patterns {
		expression, err := regexp.Compile(pattern)
		if err == nil && expression.Match(body) {
			matched = append(matched, strconv.Itoa(index))
		}
	}
	if len(matched) == 0 {
		return "none", true
	}
	return strings.Join(matched, ","), true
}

func sqlBusinessOutcome(response model.Response) (string, bool) {
	candidates := sqlBusinessOutcomeCandidates(response)
	if len(candidates) == 0 {
		return "", false
	}
	return candidates[0].key + ":" + candidates[0].value, true
}

func sqlBusinessOutcomes(response model.Response) map[string]string {
	candidates := sqlBusinessOutcomeCandidates(response)
	result := make(map[string]string, len(candidates))
	for _, candidate := range candidates {
		// The complete path prevents a nested data-row "code" from masking the
		// response envelope's status field.
		result[candidate.path] = candidate.key + ":" + candidate.value
	}
	return result
}

func sqlBusinessOutcomeCandidates(response model.Response) []sqlOutcomeCandidate {
	var value any
	decoder := json.NewDecoder(strings.NewReader(response.Text()))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil
	}
	candidates := make([]sqlOutcomeCandidate, 0, 4)
	collectSQLBusinessOutcomes(value, "$", &candidates)
	if len(candidates) == 0 {
		return nil
	}
	sort.SliceStable(candidates, func(left, right int) bool {
		if candidates[left].priority != candidates[right].priority {
			return candidates[left].priority < candidates[right].priority
		}
		return candidates[left].path < candidates[right].path
	})
	return candidates
}

type sqlOutcomeCandidate struct {
	key      string
	value    string
	path     string
	priority int
}

var sqlOutcomePriorities = map[string]int{
	"code": 0, "retcode": 1, "returncode": 2, "resultcode": 3,
	"errorcode": 4, "status": 5, "success": 6, "errno": 7,
}

func collectSQLBusinessOutcomes(value any, path string, result *[]sqlOutcomeCandidate) {
	switch current := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := current[key]
			normalizedKey := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(key))
			if priority, ok := sqlOutcomePriorities[normalizedKey]; ok {
				if scalar, valid := sqlOutcomeScalar(child); valid {
					*result = append(*result, sqlOutcomeCandidate{
						key: normalizedKey, value: scalar, path: path + "." + key, priority: priority,
					})
				}
			}
			collectSQLBusinessOutcomes(child, path+"."+key, result)
		}
	case []any:
		// Inspect a bounded prefix. Business envelopes are normally in the first
		// object; bounding prevents a large result array from dominating SQL
		// decision cost while still supporting array-root legacy APIs.
		limit := min(len(current), 16)
		for index := 0; index < limit; index++ {
			collectSQLBusinessOutcomes(current[index], path+"["+strconv.Itoa(index)+"]", result)
		}
	}
}

func sqlOutcomeScalar(value any) (string, bool) {
	switch current := value.(type) {
	case json.Number:
		return current.String(), true
	case string:
		normalized := strings.ToLower(strings.TrimSpace(current))
		return normalized, normalized != ""
	case bool:
		return strconv.FormatBool(current), true
	default:
		return "", false
	}
}

func validConditionalErrorResponses(ctx *Context, responses ...model.Response) bool {
	for _, response := range responses {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
			response.StatusCode == http.StatusNotAcceptable || response.StatusCode == http.StatusTooManyRequests ||
			diff.LikelyAuthDenied(response, ctx.Config) {
			return false
		}
	}
	return true
}

func sendPairConfirmation(ctx *Context, point httpraw.InsertionPoint, original string, pair payloadPair, progress func()) ([]model.Response, []*httpraw.Request, error) {
	rules := []config.PayloadRule{pair.left, pair.right, pair.right, pair.left}
	requests := make([]*httpraw.Request, 0, len(rules))
	for _, rule := range rules {
		request, err := ctx.Mutate(point, expandPayload(rule.Payload, map[string]string{"value": original}))
		if err != nil {
			ctx.ResolveMutationFailed(len(rules))
			return nil, nil, nil
		}
		requests = append(requests, request)
	}
	cohort, err := ctx.ReserveCohort(len(requests))
	if err != nil {
		if err == ErrPluginBudgetExhausted {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	defer cohort.Close()
	responses := make([]model.Response, 0, len(requests))
	for _, request := range requests {
		response, err := cohort.Send(request)
		if err != nil {
			return nil, nil, err
		}
		responses = append(responses, response)
		progress()
	}
	return responses, requests, nil
}

func pairPayloads(payloads []config.PayloadRule, leftKind, rightKind string) []payloadPair {
	left := make(map[string][]config.PayloadRule)
	right := make(map[string][]config.PayloadRule)
	var groupOrder []string
	knownGroup := make(map[string]bool)
	for _, payload := range payloads {
		group := payload.Group
		if group == "" {
			group = "default"
		}
		switch payload.Kind {
		case leftKind:
			left[group] = append(left[group], payload)
		case rightKind:
			right[group] = append(right[group], payload)
		default:
			continue
		}
		if !knownGroup[group] {
			knownGroup[group] = true
			groupOrder = append(groupOrder, group)
		}
	}
	result := make([]payloadPair, 0, len(groupOrder))
	seen := make(map[string]bool)
	for _, group := range groupOrder {
		// Pair duplicate group members by configuration order rather than
		// silently retaining only the last map assignment. An unmatched rule is
		// intentionally ignored; the configuration linter reports it separately.
		count := min(len(left[group]), len(right[group]))
		for index := 0; index < count; index++ {
			pair := payloadPair{group: group, left: left[group][index], right: right[group][index]}
			// PostgreSQL-compatible GaussDB rules often intentionally use the same
			// SQL text. Execute an identical control/probe pair only once.
			key := pair.left.Kind + "\x00" + pair.left.Payload + "\x00" + pair.left.Expected + "\x00" + pair.right.Kind + "\x00" + pair.right.Payload + "\x00" + pair.right.Expected
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, pair)
		}
	}
	return result
}

type compiledPattern struct {
	rule config.DetectionRule
	re   *regexp.Regexp
}

type sqlPatternMatch struct {
	name       string
	text       string
	severity   string
	confidence string
}

func (m sqlPatternMatch) severityConfidence() (model.Severity, model.Confidence) {
	severity, confidence := model.SeverityHigh, model.ConfidenceCertain
	if m.severity != "" {
		severity = model.ParseSeverity(m.severity, severity)
	}
	if m.confidence != "" {
		confidence = model.ParseConfidence(m.confidence, confidence)
	}
	return severity, confidence
}

func compileDetectionPatterns(rules []config.DetectionRule) []compiledPattern {
	result := make([]compiledPattern, 0, len(rules))
	for _, rule := range rules {
		if re, err := regexp.Compile(rule.Pattern); err == nil {
			result = append(result, compiledPattern{rule: rule, re: re})
		}
	}
	return result
}

func compileSQLDetectionPatterns(rules []config.DetectionRule, simplified []string) []compiledPattern {
	return compileSQLDetectionPatternsWithConfidence(rules, simplified, "firm")
}

func compileSQLDetectionPatternsWithConfidence(rules []config.DetectionRule, simplified []string, configuredConfidence string) []compiledPattern {
	merged := append([]config.DetectionRule(nil), rules...)
	if model.ParseConfidence(configuredConfidence, model.ConfidenceFirm) == model.ConfidenceCertain {
		configuredConfidence = "certain"
	} else if model.ParseConfidence(configuredConfidence, model.ConfidenceFirm) == model.ConfidenceTentative {
		configuredConfidence = "tentative"
	} else {
		configuredConfidence = "firm"
	}
	for index, pattern := range simplified {
		merged = append(merged, config.DetectionRule{
			Name:     fmt.Sprintf("前台数据库报错特征 #%d", index+1),
			Pattern:  pattern,
			Severity: "high",
			// A free-form expression may be as broad as "error", so the default
			// remains firm. Administrators may explicitly promote well-scoped
			// vendor expressions through SQLiErrorConfidence.
			Confidence: configuredConfidence,
		})
	}
	return compileDetectionPatterns(merged)
}

func firstPatternMatch(patterns []compiledPattern, body []byte) string {
	return firstPatternRule(patterns, body).text
}

func firstPatternRule(patterns []compiledPattern, body []byte) sqlPatternMatch {
	for _, pattern := range patterns {
		if match := pattern.re.Find(body); len(match) > 0 {
			return sqlPatternMatch{name: pattern.rule.Name, text: string(match), severity: pattern.rule.Severity, confidence: pattern.rule.Confidence}
		}
	}
	return sqlPatternMatch{}
}

// bestPatternRule chooses the most valuable matching evidence rather than the
// first configured regexp. Explicit database/JDBC signals outrank generic
// framework text, then configured severity and confidence decide.
func bestPatternRule(patterns []compiledPattern, body []byte) sqlPatternMatch {
	best := sqlPatternMatch{}
	bestScore := -1
	for _, pattern := range patterns {
		match := pattern.re.Find(body)
		if len(match) == 0 {
			continue
		}
		candidate := sqlPatternMatch{
			name: pattern.rule.Name, text: string(match),
			severity: pattern.rule.Severity, confidence: pattern.rule.Confidence,
		}
		score := sqlPatternValue(candidate)
		if score > bestScore {
			best, bestScore = candidate, score
		}
	}
	return best
}

func bestNovelPatternRule(patterns []compiledPattern, body []byte, baseline map[string]bool) sqlPatternMatch {
	best := sqlPatternMatch{}
	bestScore := -1
	for _, pattern := range patterns {
		if baseline[pattern.rule.Name] {
			continue
		}
		match := pattern.re.Find(body)
		if len(match) == 0 {
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
	return best
}

func bestCommonPatternRules(patterns []compiledPattern, left, right []byte, excluded map[string]bool) (sqlPatternMatch, sqlPatternMatch) {
	bestLeft, bestRight := sqlPatternMatch{}, sqlPatternMatch{}
	bestScore := -1
	for _, pattern := range patterns {
		if excluded[pattern.rule.Name] {
			continue
		}
		leftMatch, rightMatch := pattern.re.Find(left), pattern.re.Find(right)
		if len(leftMatch) == 0 || len(rightMatch) == 0 {
			continue
		}
		candidate := sqlPatternMatch{
			name: pattern.rule.Name, text: string(leftMatch),
			severity: pattern.rule.Severity, confidence: pattern.rule.Confidence,
		}
		score := sqlPatternValue(candidate)
		if score > bestScore {
			bestScore = score
			bestLeft = candidate
			bestRight = sqlPatternMatch{
				name: pattern.rule.Name, text: string(rightMatch),
				severity: pattern.rule.Severity, confidence: pattern.rule.Confidence,
			}
		}
	}
	return bestLeft, bestRight
}

func sqlPatternValue(match sqlPatternMatch) int {
	severityValue, confidenceValue := match.severityConfidence()
	score := 0
	switch severityValue {
	case model.SeverityCritical:
		score += 500
	case model.SeverityHigh:
		score += 400
	case model.SeverityMedium:
		score += 300
	case model.SeverityLow:
		score += 200
	default:
		score += 100
	}
	switch confidenceValue {
	case model.ConfidenceCertain:
		score += 40
	case model.ConfidenceFirm:
		score += 25
	default:
		score += 10
	}
	lower := strings.ToLower(match.name)
	for _, marker := range []string{"mysql", "postgres", "gauss", "jdbc", "mybatis", "sqlstate", "数据库", "存储过程", "callablestatement"} {
		if strings.Contains(lower, marker) {
			score += 20
			break
		}
	}
	if strings.Contains(lower, "通用") {
		score -= 10
	}
	return score
}

func sqlBooleanDifferential(
	ctx *Context,
	baselineStability float64,
	trueOne, falseOne, falseTwo, trueTwo model.Response,
	trueOneSimilarity, falseOneSimilarity, falseTwoSimilarity, trueTwoSimilarity float64,
	trueConsistent, falseConsistent, statusMatches bool,
) (confirmed, exactOracle, businessOracle bool) {
	if !trueConsistent || !falseConsistent || !statusMatches {
		return false, false, false
	}

	exactOracle = baselineStability >= 0.95 &&
		sqlEquivalentResponse(ctx.Baseline, trueOne, ctx.Config) &&
		sqlEquivalentResponse(ctx.Baseline, trueTwo, ctx.Config) &&
		sqlEquivalentResponse(falseOne, falseTwo, ctx.Config) &&
		!sqlEquivalentResponse(ctx.Baseline, falseOne, ctx.Config)
	businessOracle = baselineStability >= 0.90 &&
		sqlBusinessOutcomeABBAConfigured(ctx.Config, ctx.Baseline, trueOne, falseOne, falseTwo, trueTwo)
	if exactOracle || businessOracle {
		return true, exactOracle, businessOracle
	}

	trueMinimum, falseMaximum, gapMinimum := 0.88, 0.72, 0.20
	switch {
	case baselineStability >= 0.97:
		// Highly stable pages can support a smaller, repeated business delta.
		trueMinimum, falseMaximum, gapMinimum = 0.86, 0.80, 0.12
	case baselineStability < 0.92:
		// Near the lower stability boundary, demand a wider separation.
		trueMinimum, falseMaximum, gapMinimum = 0.92, 0.68, 0.24
	}
	confirmed = trueOneSimilarity >= trueMinimum &&
		trueTwoSimilarity >= trueMinimum &&
		falseOneSimilarity <= falseMaximum &&
		falseTwoSimilarity <= falseMaximum &&
		min(trueOneSimilarity-falseOneSimilarity, trueTwoSimilarity-falseTwoSimilarity) >= gapMinimum
	return confirmed, false, false
}

// sqlEquivalentResponse deliberately avoids segment-sampled equality for long
// bodies. Sampling is useful for bounded similarity, but must not turn two
// different multi-megabyte JSP responses into an "exact recovery" signal.
func sqlEquivalentResponse(left, right model.Response, cfg config.Config) bool {
	_ = cfg
	if left.StatusCode != right.StatusCode {
		return false
	}
	// "Exact" recovery must retain inline JSON/script data and multiplicity.
	// The general differential normalizer intentionally removes script/style and
	// dynamic keys, which is useful for similarity but too lossy for this strict
	// branch.
	return bytes.Equal(left.Body, right.Body)
}

func requiredSQLRecoverySimilarity(baseline model.Response, stability float64) float64 {
	threshold := 0.94
	// Stable, long legacy JSP pages often contain a very small business delta;
	// exact/full-body checks still guard the subtle path, while a slightly lower
	// recovery threshold avoids losing it to harmless markup variation.
	if len(baseline.Body) >= 250_000 && stability >= 0.96 {
		threshold = 0.92
	} else if stability < 0.92 {
		threshold = 0.96
	}
	return threshold
}

func validDifferentialResponses(ctx *Context, responses []model.Response) bool {
	for _, response := range responses {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
			response.StatusCode == http.StatusNotAcceptable || response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= 500 || diff.LikelyAuthDenied(response, ctx.Config) {
			return false
		}
	}
	return true
}

func validQuoteRecoveryResponses(ctx *Context, brokenOne, repairedOne, repairedTwo, brokenTwo model.Response) bool {
	responses := []model.Response{brokenOne, repairedOne, repairedTwo, brokenTwo}
	for _, response := range responses {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden ||
			response.StatusCode == http.StatusNotAcceptable || response.StatusCode == http.StatusTooManyRequests ||
			diff.LikelyAuthDenied(response, ctx.Config) {
			return false
		}
	}
	// A single quote may legitimately surface as a framework-generated 500 even
	// when no database keyword is returned. Both broken responses must agree,
	// while the repaired pair must remain non-5xx and match the baseline status.
	return brokenOne.StatusCode == brokenTwo.StatusCode &&
		repairedOne.StatusCode < 500 && repairedTwo.StatusCode < 500
}

func responseJitter(responses []model.Response) time.Duration {
	if len(responses) < 2 {
		return 0
	}
	minimum, maximum := responses[0].Elapsed, responses[0].Elapsed
	for _, response := range responses[1:] {
		minimum = min(minimum, response.Elapsed)
		maximum = max(maximum, response.Elapsed)
	}
	return maximum - minimum
}

func expectedDelay(value string) time.Duration {
	seconds, err := strconv.ParseFloat(value, 64)
	if err != nil || seconds <= 0 || seconds > 10 {
		seconds = 2
	}
	return time.Duration(seconds * float64(time.Second))
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}
