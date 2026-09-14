package plugin

import (
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type SQLInjectionDeep struct{}

func (SQLInjectionDeep) Meta() model.PluginMeta {
	meta := StandardMeta("sqli_deep", "SQL 注入（深度）", "包含快速；扩展引号/括号/注释布尔差分，ORDER BY、LIMIT/OFFSET、MyBatis 动态片段，MySQL/PostgreSQL 时间及堆叠探测；延迟须通过双时长复核。", "active", true)
<<<<<<< HEAD
	meta.Version = "3.9.0"
=======
	meta.Version = "3.8.3"
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
	return meta
}

type sqlPhase struct {
	plugin Plugin
	ruleID string
	rule   config.PluginRuleConfig
}

<<<<<<< HEAD
// Round-robin phases give all parameters a cheap Boolean screen first.
// Four common timing closures precede the broad syntax/dialect fallback.
=======
// Phase order is per parameter, avoiding a full-interface error/Boolean sweep
// consuming the timing budget. Known sorting/pagination sinks go first; four
// common timing closures precede the broader syntax and dialect fallback.
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
func sqlDeepPhases(point httpraw.InsertionPoint, cfg config.Config) []sqlPhase {
	order := cfg.PluginRules["sqli_order_by"]
	order.Payloads = nil
	for _, p := range cfg.PluginRules["sqli_order_by"].Payloads {
		if p.Kind != "time_control" && p.Kind != "time_delay" {
			order.Payloads = append(order.Payloads, p)
		}
	}
	first, rest := cfg.PluginRules["sqli_timing"], cfg.PluginRules["sqli_timing"]
	first.Payloads, rest.Payloads = nil, nil
	pairs := prioritizeSQLTimingPairs(pairPayloads(cfg.PluginRules["sqli_timing"].Payloads, "time_control", "time_delay"), point)
	for i, pair := range pairs {
		if i < 4 {
			first.Payloads = append(first.Payloads, pair.left, pair.right)
		} else {
			rest.Payloads = append(rest.Payloads, pair.left, pair.right)
		}
	}
	if len(namedSQLContextPoints([]httpraw.InsertionPoint{point}, order.ParameterNames)) > 0 {
		for _, pair := range orderByPairsForPoint(pairPayloads(cfg.PluginRules["sqli_order_by"].Payloads, "time_control", "time_delay"), point) {
			first.Payloads = append(first.Payloads, pair.left, pair.right)
		}
	}
<<<<<<< HEAD
	// Round zero gives each input the cheap Boolean closures before deep work.
	screen := cfg.PluginRules["sqli"]
	screen.Payloads = nil
	for _, pair := range normalSQLBooleanPair(pairPayloads(cfg.PluginRules["sqli"].Payloads, "boolean_true", "boolean_false"), point) {
		screen.Payloads = append(screen.Payloads, pair.left, pair.right)
	}
	return []sqlPhase{
		{SQLInjection{}, "sqli", screen},
		{SQLInjectionTiming{}, "sqli_timing", first},
=======
	return []sqlPhase{
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
		{SQLInjection{}, "sqli", cfg.PluginRules["sqli"]},
		{SQLOrderBy{}, "sqli_order_by", order},
		{SQLLimit{}, "sqli_limit", cfg.PluginRules["sqli_limit"]},
		{MyBatisDynamicSQL{}, "mybatis_dynamic_sql", cfg.PluginRules["mybatis_dynamic_sql"]},
<<<<<<< HEAD
=======
		{SQLInjectionTiming{}, "sqli_timing", first},
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
		{SQLInjectionExtended{}, "sqli_extended", cfg.PluginRules["sqli_extended"]},
		{SQLInjectionTiming{}, "sqli_timing", rest},
	}
}

func sqlPhaseConfig(cfg config.Config, phase sqlPhase) config.Config {
	rules := make(map[string]config.PluginRuleConfig, len(cfg.PluginRules))
	for k, v := range cfg.PluginRules {
		rules[k] = v
	}
	rules[phase.ruleID] = phase.rule
	cfg.PluginRules = rules
	return cfg
}

func estimateSQLDeep(request *httpraw.Request, points []httpraw.InsertionPoint, mode string, cfg config.Config) int {
	total := 0
	for _, point := range prioritizeSQLPoints(points) {
		for _, phase := range sqlDeepPhases(point, cfg) {
			total += estimateRequests(phase.ruleID, request, []httpraw.InsertionPoint{point}, mode, sqlPhaseConfig(cfg, phase))
		}
	}
	return total
}

func (p SQLInjectionDeep) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	points, cfg, progress := ctx.Points, ctx.Config, ctx.Progress
	defer func() { ctx.Points, ctx.Config, ctx.Progress = points, cfg, progress }()
	total := estimateSQLDeep(ctx.Request, points, ctx.Mode, cfg)
	resolved := 0
<<<<<<< HEAD
	ordered := prioritizeSQLPoints(points)
	pending := make([][]model.Finding, len(ordered))
	confirmed := make([]bool, len(ordered))
	collect := func() []model.Finding {
		var findings []model.Finding
		for _, items := range pending {
			findings = append(findings, items...)
		}
		return findings
	}
	rounds := 0
	if len(ordered) > 0 {
		rounds = len(sqlDeepPhases(ordered[0], cfg))
	}
	for round := 0; round < rounds; round++ {
		for index, point := range ordered {
			ctx.Points = []httpraw.InsertionPoint{point}
			phase := sqlDeepPhases(point, cfg)[round]
			ctx.Config = sqlPhaseConfig(cfg, phase)
			estimate := estimateRequests(phase.ruleID, ctx.Request, ctx.Points, ctx.Mode, ctx.Config)
			if confirmed[index] {
				ctx.ResolveAdaptivePruned(estimate)
				resolved += estimate
				progress(meta.ID, min(total, resolved), max(total, 1))
=======
	var findings []model.Finding
	for _, point := range prioritizeSQLPoints(points) {
		ctx.Points = []httpraw.InsertionPoint{point}
		var pending []model.Finding
		confirmed := false
		for _, phase := range sqlDeepPhases(point, cfg) {
			ctx.Config = sqlPhaseConfig(cfg, phase)
			estimate := estimateRequests(phase.ruleID, ctx.Request, ctx.Points, ctx.Mode, ctx.Config)
			if confirmed {
				ctx.ResolveAdaptivePruned(estimate)
				resolved += estimate
				progress(meta.ID, resolved, max(total, 1))
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
				continue
			}
			ctx.Progress = func(_ string, done, _ int) { progress(meta.ID, min(total, resolved+done), max(total, 1)) }
			results, err := phase.plugin.Scan(ctx)
			for _, finding := range results {
				finding.PluginID = meta.ID
				if finding.Confidence == model.ConfidenceCertain {
<<<<<<< HEAD
					pending[index] = []model.Finding{finding}
					confirmed[index] = true
					break
				}
				if len(pending[index]) == 0 {
					pending[index] = append(pending[index], finding)
				}
			}
			if err != nil {
				return collect(), err
=======
					pending = []model.Finding{finding}
					confirmed = true
					break
				}
				if len(pending) == 0 {
					pending = append(pending, finding)
				}
			}
			if err != nil {
				return append(findings, pending...), err
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
			}
			resolved += estimate
			progress(meta.ID, min(total, resolved), max(total, 1))
		}
<<<<<<< HEAD
	}
	return collect(), nil
=======
		findings = append(findings, pending...)
	}
	return findings, nil
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
}
