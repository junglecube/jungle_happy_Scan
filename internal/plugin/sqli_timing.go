package plugin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

var sqlSleepCall = regexp.MustCompile(`(?i)\b(?:pg_sleep|sleep)\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)`)

// Derive both the zero and second-dose probes from the delay SQL itself. Only
// the sleep argument may vary: changing a Boolean tail changes query workload.
func sqlTimingDose(pair payloadPair, dose time.Duration) (string, bool) {
	matched := false
	expected := expectedDelay(pair.right.Expected)
	payload := sqlSleepCall.ReplaceAllStringFunc(pair.right.Payload, func(call string) string {
		parts := sqlSleepCall.FindStringSubmatchIndex(call)
		value, _ := strconv.ParseFloat(call[parts[2]:parts[3]], 64)
		if absDuration(time.Duration(value*float64(time.Second))-expected) > time.Millisecond {
			return call
		}
		matched = true
		return call[:parts[2]] + strconv.FormatFloat(dose.Seconds(), 'f', -1, 64) + call[parts[3]:]
	})
	return payload, matched
}

func validSQLTimingResponses(ctx *Context, responses []model.Response) bool {
	if len(responses) == 0 {
		return false
	}
	for _, r := range responses {
		// Stable application HTTP 500 is admissible: an executed expression may
		// subsequently produce an ORM error. Gateway/timeouts and access blocks
		// are never positive evidence, nor is a status change between doses.
		if r.StatusCode < 200 || r.StatusCode >= 600 || r.StatusCode != responses[0].StatusCode || r.Elapsed <= 0 ||
			r.StatusCode == 401 || r.StatusCode == 403 || r.StatusCode == 406 || r.StatusCode == 408 ||
			r.StatusCode == 429 || r.StatusCode == 502 || r.StatusCode == 503 || r.StatusCode == 504 ||
			diff.LikelyAuthDenied(r, ctx.Config) {
			return false
		}
	}
	return true
}

// A-B screens cheaply. Only a plausible delay spends the remaining B-A-C-A
// reservation. C is half the B dose. Fixed slow/WAF responses fail the slope
// check even when a traditional A-B-B-A test would have accepted them.
func probeSQLTiming(ctx *Context, meta model.PluginMeta, point httpraw.InsertionPoint, pair payloadPair, progress func(int)) (model.Finding, bool, error) {
	const slots = 6
	expected := expectedDelay(pair.right.Expected)
	shortDose := expected / 2
	zeroSQL, ok := sqlTimingDose(pair, 0)
	shortSQL, shortOK := sqlTimingDose(pair, shortDose)
	if !ok || !shortOK {
		// Custom timing functions need a dose-aware adapter; do not silently
		// promote an unverifiable custom delay into a confirmed vulnerability.
		ctx.ResolveAdaptivePruned(slots)
		progress(slots)
		return model.Finding{}, false, nil
	}
	values := []string{zeroSQL, pair.right.Payload, pair.right.Payload, zeroSQL, shortSQL, zeroSQL}
	requests := make([]*httpraw.Request, slots)
	for i, value := range values {
		request, err := ctx.Mutate(point, expandPayload(value, map[string]string{"value": point.Value}))
		if err != nil {
			ctx.ResolveMutationFailed(slots)
			progress(slots)
			return model.Finding{}, false, nil
		}
		requests[i] = request
	}
	cohort, err := ctx.ReserveCohort(slots)
	if err != nil {
		return model.Finding{}, false, err
	}
	defer cohort.Close()
	responses := make([]model.Response, 0, slots)
	margin := max(800*time.Millisecond, expected*13/20)
	for i, request := range requests {
		r, err := cohort.Send(request)
		progress(1)
		if err != nil {
			return model.Finding{}, false, err
		}
		responses = append(responses, r)
		if i == 1 && (!validSQLTimingResponses(ctx, responses) || r.Elapsed-responses[0].Elapsed < margin) {
			ctx.ResolveAdaptivePruned(4)
			progress(4)
			return model.Finding{}, false, nil
		}
	}
	if !validSQLTimingResponses(ctx, responses) {
		return model.Finding{}, false, nil
	}
	controls := []model.Response{responses[0], responses[3], responses[5]}
	jitter := responseJitter(controls)
	// Local bracketed controls avoid letting one cold baseline handshake set
	// an impossibly high threshold for every subsequent parameter.
	if jitter > max(350*time.Millisecond, expected/5) {
		return model.Finding{}, false, nil
	}
	noise := max(350*time.Millisecond, jitter*2)
	longOne := responses[1].Elapsed - responses[0].Elapsed
	longTwo := responses[2].Elapsed - responses[3].Elapsed
	short := responses[4].Elapsed - (responses[3].Elapsed+responses[5].Elapsed)/2
	longMean := (longOne + longTwo) / 2
	if min(longOne, longTwo) < margin || absDuration(longOne-longTwo) > max(noise, expected/3) ||
		absDuration(longMean-expected) > max(noise, expected/3) ||
		absDuration(short-shortDose) > max(noise, shortDose/3) || short < shortDose/2 ||
		absDuration((longMean-short)-(expected-shortDose)) > max(noise, expected/4) {
		return model.Finding{}, false, nil
	}
	roles := []string{"control", "delay", "delay", "control", "short_delay", "control"}
	var evidence []model.Evidence
	for i := range responses {
		metrics := sqlPairMetrics(pair, i+1, roles[i], "L4", map[string]any{
			"elapsed_ms": responses[i].Elapsed.Milliseconds(), "expected_delay_ms": expected.Milliseconds(),
			"short_delay_ms": shortDose.Milliseconds(), "local_jitter_ms": jitter.Milliseconds(),
			"dose_confirmed": true, "long_delta_ms": longMean.Milliseconds(), "short_delta_ms": short.Milliseconds(),
			"payload_rule": pair.right.Name,
		})
		metrics["pair_order"] = "A-B-B-A-C-A"
		evidence = append(evidence, ctx.Evidence(fmt.Sprintf("时间差分 %d：%s", i+1, roles[i]), requests[i], &responses[i], metrics))
	}
	title := "SQL 时间盲注"
	if strings.Contains(pair.group, "stacked") {
		title = "SQL 堆叠时间盲注"
	}
	return Finding(meta, title, model.SeverityHigh, model.ConfidenceCertain, point.Label(),
		"同一 SQL 结构的零延迟/长延迟经 A-B-B-A 复核，再以半时长 C 和零延迟 A 验证耗时随设定值变化；控制响应稳定，排除了固定慢响应和明显网络抖动。",
		"使用参数绑定，MyBatis 值参数采用 #{}；动态标识符采用白名单，并限制多语句执行及存储过程动态拼接。", evidence, "OWASP WSTG-INPV-05"), true, nil
}
