package plugin

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestSQLDoubleQuoteBooleanAndTiming(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"rows":[{"id":"1"}]}`)}

	t.Run("boolean", func(t *testing.T) {
		ctx := testContext(t, "GET /Less-4/?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			value := parsed.Query().Get("id")
			if strings.Contains(value, `"731"="732`) {
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"rows":[]}`)}, nil
			}
			return baseline, nil
		}
		findings, err := (SQLInjectionExtended{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL 布尔盲注" {
			t.Fatalf("double-quote Boolean pair was missed: err=%v findings=%+v", err, findings)
		}
	})

	t.Run("timing", func(t *testing.T) {
		ctx := testContext(t, "GET /Less-10/?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{
			{StatusCode: 200, Headers: jsonHeader(), Body: baseline.Body, Elapsed: 20 * time.Millisecond},
			{StatusCode: 200, Headers: jsonHeader(), Body: baseline.Body, Elapsed: 25 * time.Millisecond},
		}
		ctx.Baseline = ctx.Baselines[0]
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			response := baseline
			response.Elapsed = 25 * time.Millisecond
			parsed, _ := url.Parse(request.Target)
			if strings.Contains(parsed.Query().Get("id"), `" AND SLEEP(2)`) {
				response.Elapsed = 2200 * time.Millisecond
			}
			return response, nil
		}
		findings, err := (SQLInjectionTiming{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL 时间盲注" {
			t.Fatalf("double-quote timing pair was missed: err=%v findings=%+v", err, findings)
		}
	})

	t.Run("query-or-select-sleep", func(t *testing.T) {
		ctx := testContext(t, "GET /search?query=abc HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{
			{StatusCode: 200, Headers: jsonHeader(), Body: baseline.Body, Elapsed: 20 * time.Millisecond},
			{StatusCode: 200, Headers: jsonHeader(), Body: baseline.Body, Elapsed: 25 * time.Millisecond},
		}
		ctx.Baseline = ctx.Baselines[0]
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			response := baseline
			response.Elapsed = 25 * time.Millisecond
			parsed, _ := url.Parse(request.Target)
			value := strings.ToLower(strings.ReplaceAll(parsed.Query().Get("query"), " ", ""))
			if strings.Contains(value, "or(selectsleep(3))") {
				response.Elapsed = 3300 * time.Millisecond
			}
			return response, nil
		}
		findings, err := (SQLInjectionTiming{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL 时间盲注" {
			t.Fatalf("query OR SELECT SLEEP timing pair was missed: err=%v findings=%+v", err, findings)
		}
	})

	t.Run("query-and-select-sleep", func(t *testing.T) {
		ctx := testContext(t, "GET /search?query=original HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{
			{StatusCode: 200, Headers: jsonHeader(), Body: baseline.Body, Elapsed: 20 * time.Millisecond},
			{StatusCode: 200, Headers: jsonHeader(), Body: baseline.Body, Elapsed: 25 * time.Millisecond},
		}
		ctx.Baseline = ctx.Baselines[0]
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			response := baseline
			response.Elapsed = 25 * time.Millisecond
			parsed, _ := url.Parse(request.Target)
			value := strings.ToLower(strings.ReplaceAll(parsed.Query().Get("query"), " ", ""))
			if value == "'and(selectsleep(3))and'1'='1" {
				response.Elapsed = 3300 * time.Millisecond
			}
			return response, nil
		}
		findings, err := (SQLInjectionTiming{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL 时间盲注" {
			t.Fatalf("query AND SELECT SLEEP timing pair was missed: err=%v findings=%+v", err, findings)
		}
	})
}

func TestSQLOrderByAndLimitContextPlugins(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200,"rows":[1,2,3]}`)}

	t.Run("order-by-conditional-error", func(t *testing.T) {
		ctx := testContext(t, "GET /items?sort=id HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			value := parsed.Query().Get("sort")
			if strings.Contains(value, "IF(731=732") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("DOUBLE value is out of range in 'exp(720)'")}, nil
			}
			return baseline, nil
		}
		findings, err := (SQLOrderBy{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL ORDER BY 条件错误注入" {
			t.Fatalf("ORDER BY conditional oracle was missed: err=%v findings=%+v", err, findings)
		}
	})

	t.Run("limit-comment-boundary", func(t *testing.T) {
		ctx := testContext(t, "GET /items?limit=10 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			value := parsed.Query().Get("limit")
			if strings.Contains(value, "'-- ") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("You have an error in your SQL syntax")}, nil
			}
			return baseline, nil
		}
		findings, err := (SQLLimit{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL LIMIT/OFFSET 注释边界注入" {
			t.Fatalf("LIMIT boundary oracle was missed: err=%v findings=%+v", err, findings)
		}
	})

	t.Run("candidate-name-guard", func(t *testing.T) {
		ctx := testContext(t, "GET /items?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		sends := 0
		ctx.SendFunc = func(_ context.Context, _ *httpraw.Request) (model.Response, error) {
			sends++
			return baseline, nil
		}
		findings, err := (SQLOrderBy{}).Scan(ctx)
		if err != nil || len(findings) != 0 || sends != 0 {
			t.Fatalf("ORDER BY plugin scanned a non-candidate parameter: sends=%d err=%v findings=%+v", sends, err, findings)
		}
	})

	t.Run("candidate-short-suffix-does-not-match-unrelated-name", func(t *testing.T) {
		points := []httpraw.InsertionPoint{{Location: "query", Name: "preorder", Value: "1", ValueType: "number"}}
		if matched := namedSQLContextPoints(points, []string{"order"}); len(matched) != 0 {
			t.Fatalf("short candidate suffix produced a false positive: %#v", matched)
		}
	})

	t.Run("postgres-gauss-order-by-normalized-candidate", func(t *testing.T) {
		ctx := testContext(t, "GET /items?page.sort_field=id HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			value := parsed.Query().Get("page.sort_field")
			if strings.Contains(value, "CASE WHEN 731=732") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`org.postgresql.util.PSQLException: invalid input syntax for type integer: "jhs731"`)}, nil
			}
			return baseline, nil
		}
		findings, err := (SQLOrderBy{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL ORDER BY 条件错误注入" {
			t.Fatalf("PostgreSQL/GaussDB ORDER BY pair or normalized candidate was missed: err=%v findings=%+v", err, findings)
		}
	})

	t.Run("postgres-gauss-limit-abba", func(t *testing.T) {
		ctx := testContext(t, "GET /items?pagination.page_size=10 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			value := parsed.Query().Get("pagination.page_size")
			if strings.Contains(value, "CASE WHEN 731=732") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`org.opengauss.util.PSQLException: invalid input syntax for integer: "jhs731"`)}, nil
			}
			return baseline, nil
		}
		findings, err := (SQLLimit{}).Scan(ctx)
		if err != nil || len(findings) != 1 || findings[0].Title != "SQL LIMIT/OFFSET 条件错误注入" {
			t.Fatalf("PostgreSQL/GaussDB LIMIT ABBA pair was missed: err=%v findings=%+v", err, findings)
		}
	})
}
