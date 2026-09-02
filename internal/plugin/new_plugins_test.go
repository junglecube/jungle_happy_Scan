package plugin

import (
	"context"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestErrorDisclosureAndNewInjectionPlugins(t *testing.T) {
	t.Run("error-disclosure", func(t *testing.T) {
		ctx := testContext(t, "GET /user?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(request.Target, "%27") || strings.Contains(request.Target, "'") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("java.lang.IllegalArgumentException: bad input\n at com.bank.UserService.query(UserService.java:81)")}, nil
			}
			return ctx.Baseline, nil
		}
		findings, err := (ErrorDisclosure{}).Scan(ctx)
		assertFinding(t, findings, err, "error_disclosure")
	})

	tests := []struct {
		name   string
		plugin Plugin
		raw    string
		truth  string
		falsey string
	}{
		{"nosql", NoSQLInjection{}, "POST /login HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"user\":\"alice\"}", `"$ne":null`, `"$eq"`},
		{"ldap", LDAPInjection{}, "GET /login?user=alice HTTP/1.1\r\nHost: bank.test\r\n\r\n", "objectClass=*)", "__jhs_no_match_731__"},
		{"xpath", XPathInjection{}, "GET /login?user=alice HTTP/1.1\r\nHost: bank.test\r\n\r\n", "731%27%3D%27731", "731%27%3D%27732"},
	}
	for _, item := range tests {
		t.Run(item.name, func(t *testing.T) {
			baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"authenticated":true,"profile":"alice"}`)}
			ctx := testContext(t, item.raw, baseline)
			ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
				raw := request.Raw(false)
				switch {
				case strings.Contains(raw, item.falsey):
					return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"authenticated":false}`)}, nil
				case strings.Contains(raw, item.truth):
					return baseline, nil
				default:
					return baseline, nil
				}
			}
			findings, err := item.plugin.Scan(ctx)
			assertFinding(t, findings, err, item.plugin.Meta().ID)
		})
	}
}

func TestNewJavaAndAPISecurityPlugins(t *testing.T) {
	t.Run("java-deserialization-entry", func(t *testing.T) {
		ctx := testContext(t, "POST /decode HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"payload\":\"normal\"}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), "rO0AB") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("java.io.StreamCorruptedException: invalid stream header")}, nil
			}
			return ctx.Baseline, nil
		}
		findings, err := (JavaDeserialization{}).Scan(ctx)
		assertFinding(t, findings, err, "java_deserialization")
	})

	t.Run("method-override", func(t *testing.T) {
		ctx := testContext(t, "POST /account HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Method == "DELETE" && request.Header("X-HTTP-Method-Override") == "" {
				return model.Response{StatusCode: 405, Headers: jsonHeader(), Body: []byte(`{"error":"method denied"}`)}, nil
			}
			if request.Header("X-HTTP-Method-Override") == "DELETE" {
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"deleted":true}`)}, nil
			}
			return ctx.Baseline, nil
		}
		findings, err := (MethodOverride{}).Scan(ctx)
		assertFinding(t, findings, err, "method_override")
	})

	t.Run("mass-assignment", func(t *testing.T) {
		ctx := testContext(t, "POST /user HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"alice\"}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"name":"alice"}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), `"isAdmin":true`) {
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"name":"alice","isAdmin":true}`)}, nil
			}
			return ctx.Baseline, nil
		}
		findings, err := (MassAssignment{}).Scan(ctx)
		assertFinding(t, findings, err, "mass_assignment")
	})

	t.Run("graphql-security", func(t *testing.T) {
		ctx := testContext(t, "POST /graphql HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"query\":\"{viewer{id}}\"}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"data":{"viewer":{"id":"1"}}}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			body := string(request.Body)
			switch {
			case strings.HasPrefix(body, "["):
				items := make([]string, 20)
				for index := range items {
					items[index] = `{"data":{"__typename":"Query"}}`
				}
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("[" + strings.Join(items, ",") + "]")}, nil
			case strings.Contains(body, "__schema"):
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`)}, nil
			case strings.Contains(body, "__jungle_happy_scan"):
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"errors":[{"message":"Did you mean viewer?"}]}`)}, nil
			default:
				return ctx.Baseline, nil
			}
		}
		findings, err := (GraphQLSecurity{}).Scan(ctx)
		if err != nil || len(findings) < 3 {
			t.Fatalf("expected GraphQL findings, got %d, err=%v", len(findings), err)
		}
	})
}
