package plugin

import (
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
)

func TestExecutionPlannerApplicabilityAndFairBudget(t *testing.T) {
	request, err := httpraw.Parse(
		"GET /api/users/42?id=1 HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=secret\r\n\r\n",
		"https",
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	points := httpraw.DiscoverAdvanced(request, cfg)
	selected, err := Select([]string{"sqli", "xxe", "file_upload", "sensitive_data"}, "standard")
	if err != nil {
		t.Fatal(err)
	}
	plans := BuildExecutionPlans(selected, request, points, "standard", cfg, 10)
	byID := make(map[string]ExecutionPlan)
	totalBudget := 0
	for _, plan := range plans {
		byID[plan.Plugin.Meta().ID] = plan
		totalBudget += plan.Budget
	}
	if byID["xxe"].Applicable || byID["file_upload"].Applicable {
		t.Fatalf("protocol-specific plugins should be skipped: %#v", byID)
	}
	if !byID["sqli"].Applicable || byID["sqli"].Budget == 0 {
		t.Fatalf("SQL injection should receive a fair active budget: %#v", byID["sqli"])
	}
	if totalBudget > 10 {
		t.Fatalf("planner exceeded global budget: %d", totalBudget)
	}
	if byID["sensitive_data"].EstimatedRequests != 0 {
		t.Fatalf("passive plugin should not consume request budget: %#v", byID["sensitive_data"])
	}
}

func TestExecutionPlannerAllowsSMSPhoneOnCapturedGETRequest(t *testing.T) {
	request, err := httpraw.Parse(
		"GET /sms/send?phone=13800138000 HTTP/1.1\r\nHost: bank.test\r\n\r\n",
		"https",
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	points := httpraw.DiscoverAdvanced(request, cfg)
	selected, err := Select([]string{"sms_abuse"}, "standard")
	if err != nil {
		t.Fatal(err)
	}
	plans := BuildExecutionPlans(selected, request, points, "standard", cfg, 100)
	if len(plans) != 1 || !plans[0].Applicable || plans[0].Budget != 60 {
		t.Fatalf("SMS phone point should receive full bombing/spraying plan: %#v", plans)
	}
}

func TestExecutionPlannerUsesGlobalBackuppathForCommandOAST(t *testing.T) {
	request, err := httpraw.Parse(
		"POST /backup HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"backuppath\":\"/safe/backup\"}",
		"https",
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	rule := cfg.PluginRules["command_injection_oast"]
	rule.ParameterNames = nil
	cfg.PluginRules["command_injection_oast"] = rule
	cfg.CommandParameterNames = []string{"backuppath"}
	points := httpraw.DiscoverAdvanced(request, cfg)
	selected, err := Select([]string{"command_injection_oast"}, "deep")
	if err != nil {
		t.Fatal(err)
	}
	plans := BuildExecutionPlans(selected, request, points, "deep", cfg, 100)
	if len(plans) != 1 || !plans[0].Applicable || plans[0].PointsTotal != 1 ||
		plans[0].EstimatedRequests != len(rule.Payloads) || plans[0].Budget != len(rule.Payloads) {
		t.Fatalf("global backuppath command OAST plan is incorrect: %#v", plans)
	}
}

func TestExecutionPlannerUsesRuntimeSQLCandidatesAndCohortQuanta(t *testing.T) {
	request, err := httpraw.Parse(
		"GET /api/items?sort=name&unrelated=value HTTP/1.1\r\nHost: bank.test\r\n\r\n",
		"https",
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	rule := cfg.PluginRules["mybatis_dynamic_sql"]
	rule.ParameterNames = nil // Runtime falls back to its canonical candidate names.
	cfg.PluginRules["mybatis_dynamic_sql"] = rule
	points := httpraw.DiscoverAdvanced(request, cfg)
	selected, err := Select([]string{"mybatis_dynamic_sql", "sqli_order_by"}, "normal")
	if err != nil {
		t.Fatal(err)
	}
	plans := BuildExecutionPlans(selected, request, points, "normal", cfg, 6)
	if len(plans) != 2 {
		t.Fatalf("unexpected plans: %#v", plans)
	}
	totalBudget := 0
	for _, plan := range plans {
		if !plan.Applicable {
			t.Fatalf("%s should use the same candidate selector as runtime: %#v", plan.Plugin.Meta().ID, plan)
		}
		if plan.PointsTotal != 1 {
			t.Fatalf("%s estimated %d candidates, want 1", plan.Plugin.Meta().ID, plan.PointsTotal)
		}
		quantum := planBudgetQuantum(plan.Plugin.Meta().ID)
		if plan.Budget%quantum != 0 {
			t.Fatalf("%s split an atomic request cohort of %d: budget=%d", plan.Plugin.Meta().ID, quantum, plan.Budget)
		}
		totalBudget += plan.Budget
	}
	if totalBudget > 6 {
		t.Fatalf("planner exceeded fragmentary global budget: %d", totalBudget)
	}
}

func TestExecutionPlannerIncludesCoreSQLQuoteGate(t *testing.T) {
	request, err := httpraw.Parse(
		"GET /api/items?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n",
		"https",
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	points := httpraw.DiscoverAdvanced(request, cfg)
	selected, err := Select([]string{"sqli"}, "normal")
	if err != nil {
		t.Fatal(err)
	}
	plans := BuildExecutionPlans(selected, request, points, "normal", cfg, 10_000)
	if len(plans) != 1 {
		t.Fatalf("unexpected SQL plan: %#v", plans)
	}
	payloads := payloadsForMode(cfg.PluginRules["sqli"], "normal")
	pairs := len(pairPayloads(payloads, "error_break", "error_repair")) +
		len(pairPayloads(payloads, "conditional_control", "conditional_error")) + 1
	want := pairs*4 + 1
	if plans[0].EstimatedRequests != want {
		t.Fatalf("SQL plan omitted the independent quote gate: got=%d want=%d", plans[0].EstimatedRequests, want)
	}
}
