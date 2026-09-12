package plugin

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestSQL381TwoPublicCapabilities(t *testing.T) {
	var ids []string
	for _, p := range Metadata() {
		if strings.HasPrefix(p.ID, "sqli") || p.ID == "mybatis_dynamic_sql" {
			ids = append(ids, p.ID)
		}
	}
	if strings.Join(ids, ",") != "sqli,sqli_deep" {
		t.Fatalf("SQL capabilities: %v", ids)
	}
	for _, ids := range [][]string{{"sqli", "sqli_deep"}, {"sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "mybatis_dynamic_sql"}} {
		selected, err := Select(ids, "normal")
		if err != nil || len(selected) != 1 || selected[0].Meta().ID != "sqli_deep" {
			t.Fatalf("duplicate/legacy selection: %v %v", selected, err)
		}
	}
}

func TestSQL381ReportedPayloadsAndClosures(t *testing.T) {
	// Synthetic HTTP response/duration fixtures, not a SQL interpreter. Exact
	// families isolate coverage while independent duration parsing checks doses.
	forms := []string{
		"' AND (SELECT SLEEP(%s)) AND '1'='1",
		"' AND (SELECT 1 FROM pg_sleep(%s)) AND '1'='2",
		"') AND 5014=(SELECT 5014 FROM pg_sleep(%s)) AND ('1'='1",
		"original' AND 5014=(SELECT 5014 FROM pg_sleep(%s)) AND '1'='1",
		"original')) AND 5014=(SELECT 5014 FROM pg_sleep(%s))-- ",
		"original%' AND (SELECT SLEEP(%s))=0 AND '%'='",
		"original'||(SELECT '' FROM pg_sleep(%s))||'",
		"original'; SELECT pg_sleep(%s);-- ",
	}
	for _, form := range forms {
		t.Run(form, func(t *testing.T) {
			baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`), Elapsed: 25 * time.Millisecond}
			ctx := testContext(t, "GET /search?query=original HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
			ctx.Baselines = []model.Response{baseline, baseline}
			// A cold initial sample must not suppress good local timing controls.
			ctx.Baselines[0].Elapsed = 2 * time.Second
			ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
				u, _ := url.Parse(request.Target)
				value := u.Query().Get("query")
				r := baseline
				parts := strings.Split(form, "%s")
				if strings.HasPrefix(value, parts[0]) && strings.HasSuffix(value, parts[1]) {
					r.Elapsed += fixtureSQLSleep(value)
				}
				return r, nil
			}
			findings, err := (SQLInjectionDeep{}).Scan(ctx)
			if err != nil || len(findings) != 1 || findings[0].PluginID != "sqli_deep" {
				t.Fatalf("miss: err=%v findings=%v", err, findings)
			}
			if len(findings[0].Evidence) != 6 || findings[0].Evidence[4].Metrics["dose_confirmed"] != true {
				t.Fatalf("missing second-dose evidence: %v", findings)
			}
		})
	}
}

func TestSQL381TimingFalsePositiveAndFailureControls(t *testing.T) {
	for _, scenario := range []string{"fixed-delay", "all-slow", "jitter", "one-spike", "auth", "rate-limit", "gateway", "status-change", "stable-500", "true-delay", "timeout", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`), Elapsed: 20 * time.Millisecond}
			ctx := testContext(t, "GET /?query=x HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
			pair := preferredSQLPair(pairPayloads(ctx.Rule("sqli_timing").Payloads, "time_control", "time_delay"), "mysql-sleep-and-select-exact-replace")[0]
			calls := 0
			ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
				calls++
				u, _ := url.Parse(request.Target)
				delay := fixtureSQLSleep(u.Query().Get("query"))
				r := baseline
				switch scenario {
				case "fixed-delay":
					if delay > 0 {
						r.Elapsed += 3 * time.Second
					}
				case "all-slow":
					r.Elapsed += 3 * time.Second
				case "jitter":
					r.Elapsed += delay
					if calls == 4 {
						r.Elapsed += time.Second
					}
				case "one-spike":
					if calls == 2 {
						r.Elapsed += 3 * time.Second
					}
				case "auth":
					r.Elapsed += delay
					r.StatusCode = 403
				case "rate-limit":
					r.Elapsed += delay
					r.StatusCode = 429
				case "gateway":
					r.Elapsed += delay
					r.StatusCode = 504
				case "status-change":
					r.Elapsed += delay
					if delay > 0 {
						r.StatusCode = 500
					}
				case "stable-500":
					r.Elapsed += delay
					r.StatusCode = 500
					r.Body = []byte(`{"error":"application failure"}`)
				case "true-delay":
					r.Elapsed += delay
				case "timeout":
					return model.Response{}, context.DeadlineExceeded
				case "cancel":
					return model.Response{}, context.Canceled
				}
				return r, nil
			}
			_, confirmed, err := probeSQLTiming(ctx, SQLInjectionDeep{}.Meta(), ctx.Points[0], pair, func(int) {})
			want := scenario == "stable-500" || scenario == "true-delay"
			if confirmed != want {
				t.Fatalf("confirmed=%v want=%v calls=%d err=%v", confirmed, want, calls, err)
			}
			if (scenario == "timeout" || scenario == "cancel") && err == nil {
				t.Fatal("transport failure was hidden")
			}
		})
	}
}

func TestSQL381FastHasNoDelayAndDeepBudgetIsHonest(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`), Elapsed: 20 * time.Millisecond}
	for _, p := range []Plugin{SQLInjection{}, SQLInjectionDeep{}} {
		ctx := testContext(t, "GET /?query=x HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		planned := estimateRequests(p.Meta().ID, ctx.Request, ctx.Points, ctx.Mode, ctx.Config)
		pruned, sent := 0, 0
		ctx.RequestBudget = planned
		ctx.OnResolution = func(kind string, n int) {
			if kind == "adaptive_pruned" {
				pruned += n
			}
		}
		ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
			sent++
			if p.Meta().ID == "sqli" && (strings.Contains(strings.ToLower(r.Target), "sleep") || strings.Contains(r.Target, "%3B")) {
				t.Fatal("fast sent a delay/stacked probe")
			}
			return baseline, nil
		}
		findings, err := p.Scan(ctx)
		if err != nil || len(findings) > 0 {
			t.Fatalf("negative target: %v %v", err, findings)
		}
		if sent+pruned != planned {
			t.Fatalf("%s plan=%d sent=%d pruned=%d", p.Meta().ID, planned, sent, pruned)
		}
		if p.Meta().ID == "sqli" && sent != 5 {
			t.Fatalf("fast clean parameter cost %d, want 5", sent)
		}
	}
	ctx := testContext(t, "GET /?query=x HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.RequestBudget = 5
	pair := pairPayloads(config.Default().PluginRules["sqli_timing"].Payloads, "time_control", "time_delay")[0]
	calls := 0
	ctx.SendFunc = func(context.Context, *httpraw.Request) (model.Response, error) { calls++; return baseline, nil }
	_, confirmed, err := probeSQLTiming(ctx, SQLInjectionDeep{}.Meta(), ctx.Points[0], pair, func(int) {})
	if !errors.Is(err, ErrPluginBudgetExhausted) || confirmed || calls != 0 {
		t.Fatalf("split cohort: calls=%d confirmed=%v err=%v", calls, confirmed, err)
	}
}
