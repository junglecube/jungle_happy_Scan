package httpraw

import (
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

func TestParseDiscoverMutateAndSessions(t *testing.T) {
	raw := "POST /api/query?name=alice&id=1 HTTP/1.1\r\n" +
		"Host: bank.test:8443\r\nContent-Type: application/json\r\n" +
		"Cookie: theme=dark; JSESSIONID=secret\r\nAuthorization: Bearer abc\r\n\r\n" +
		`{"user":{"id":"12","active":true},"page":1}`
	req, err := Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	if req.Host() != "bank.test" {
		t.Fatalf("unexpected host %q", req.Host())
	}
	points := Discover(req, false)
	if len(points) != 5 {
		t.Fatalf("expected 5 insertion points, got %d: %#v", len(points), points)
	}
	var idPoint InsertionPoint
	for _, point := range points {
		if point.Path == "user.id" {
			idPoint = point
		}
	}
	mutated, err := Mutate(req, idPoint, "12'")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mutated.Body), `"id":"12'"`) {
		t.Fatalf("JSON field was not mutated: %s", mutated.Body)
	}
	removed, names := RemoveSessions(req, config.SessionKeyList{"JSESSIONID", "Authorization"})
	if len(names) != 2 || strings.Contains(removed.Header("Cookie"), "JSESSIONID") || removed.Header("Authorization") != "" {
		t.Fatalf("session fields were not removed: %#v %q", names, removed.Raw(false))
	}
	if !strings.Contains(removed.Header("Cookie"), "theme=dark") {
		t.Fatal("non-session cookie should be preserved")
	}
}

func TestDiscoverClassifiesTextScalarValueTypes(t *testing.T) {
	req, err := Parse("GET /items?integer=-12&decimal=.75&scientific=6.02e23&date=2026-07-28&enabled=TRUE&id=550e8400-e29b-41d4-a716-446655440000&name=alice HTTP/1.1\r\nHost: bank.test\r\n\r\n", "https")
	if err != nil {
		t.Fatal(err)
	}
	points := Discover(req, false)
	got := make(map[string]string, len(points))
	for _, point := range points {
		got[point.Name] = point.ValueType
	}
	want := map[string]string{
		"integer": "number", "decimal": "number", "scientific": "number",
		"date": "date", "enabled": "bool", "id": "uuid", "name": "string",
	}
	for name, valueType := range want {
		if got[name] != valueType {
			t.Fatalf("%s classified as %q, want %q (all=%#v)", name, got[name], valueType, got)
		}
	}
}

func TestNestedJSONArrayDiscoveryMutationAndLocationIndependentSessions(t *testing.T) {
	raw := "POST /api/batch?token=query-secret&safe=1 HTTP/1.1\r\n" +
		"Host: bank.test\r\nContent-Type: application/json\r\n" +
		"Cookie: theme=dark; JSESSIONID=cookie-secret\r\nAuthorization: Bearer header-secret\r\n\r\n" +
		`[{"users":[{"id":"12","token":"json-secret","profile":{"sessionId":"nested-secret"}}]},{"id":2,"safe":true}]`
	req, err := Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	points := Discover(req, false)
	var nestedID InsertionPoint
	for _, point := range points {
		if point.Path == "[0].users[0].id" {
			nestedID = point
		}
	}
	if nestedID.Path == "" {
		t.Fatalf("nested JSON array insertion point was not discovered: %#v", points)
	}
	mutated, err := Mutate(req, nestedID, "12'")
	if err != nil || !strings.Contains(string(mutated.Body), `"id":"12'"`) {
		t.Fatalf("nested JSON array field was not mutated: err=%v body=%s", err, mutated.Body)
	}

	keys := config.SessionKeyList{"JSESSIONID", "Authorization", "token", "sessionId"}
	removed, removedNames := RemoveSessions(req, keys)
	for _, secret := range []string{"query-secret", "cookie-secret", "header-secret", "json-secret", "nested-secret"} {
		if strings.Contains(removed.Raw(false), secret) {
			t.Fatalf("session value %q was not removed: %s", secret, removed.Raw(false))
		}
	}
	for _, safe := range []string{"safe=1", "theme=dark", `"safe":true`, `"id":"12"`} {
		if !strings.Contains(removed.Raw(false), safe) {
			t.Fatalf("non-session value %q should be preserved: %s", safe, removed.Raw(false))
		}
	}
	if len(removedNames) != 5 {
		t.Fatalf("expected five session locations to be removed, got %#v", removedNames)
	}

	invalidated, changedNames := InvalidateSessions(req, keys, "invalid-session")
	if len(changedNames) != 5 || strings.Count(invalidated.Raw(false), "invalid-session") != 5 {
		t.Fatalf("all nested session locations should be invalidated: names=%#v raw=%s", changedNames, invalidated.Raw(false))
	}
}

func TestEffectiveSessionIdentifiersFindCustomCredentialNames(t *testing.T) {
	req, err := Parse("GET /private?accessTicket=abc HTTP/1.1\r\nHost: bank.test\r\nCookie: theme=dark\r\ndesSessionId: secret\r\n\r\n", "https")
	if err != nil {
		t.Fatal(err)
	}
	keys := EffectiveSessionIdentifiers(req, config.SessionKeyList{"cookie"})
	removed, names := RemoveSessions(req, keys)
	if removed.Header("desSessionId") != "" || strings.Contains(removed.Target, "accessTicket") || len(names) < 3 {
		t.Fatalf("effective session discovery did not remove all credentials: keys=%#v names=%#v raw=%s", keys, names, removed.Raw(false))
	}
}

func TestMultipartDiscoveryAndFileMutation(t *testing.T) {
	body := "--abc\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n" +
		"--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"safe.txt\"\r\nContent-Type: text/plain\r\n\r\noriginal\r\n--abc--\r\n"
	raw := "POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=abc\r\n\r\n" + body
	req, err := Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	points := Discover(req, false)
	if len(points) != 2 || points[0].Name != "note" || points[0].Value != "hello" ||
		points[1].Location != "multipart_filename" || points[1].Value != "safe.txt" {
		t.Fatalf("unexpected multipart points: %#v", points)
	}
	mutated, err := MutateMultipartFile(req, "probe.jsp", "application/octet-stream", []byte("CANARY"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(mutated.Body)
	for _, expected := range []string{`filename="probe.jsp"`, "Content-Type: application/octet-stream", "CANARY", `name="note"`} {
		if !strings.Contains(text, expected) {
			t.Fatalf("multipart mutation missing %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "original") {
		t.Fatal("original file content should be replaced")
	}
}

func TestMultipartMetadataMutationPreservesOriginalFileBytes(t *testing.T) {
	body := "--abc\r\nContent-Disposition: form-data; name=\"photo.jpg\"; filename=\"photo.jpg\"\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n1234\r\n--abc--\r\n"
	req, err := Parse("POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=abc\r\n\r\n"+body, "http")
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := MutateMultipartFileIdentityMetadataAt(req, 0, "probe.jspx", "probe.jspx", "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	text := string(mutated.Body)
	if !strings.Contains(text, `name="probe.jspx"; filename="probe.jspx"`) ||
		!strings.Contains(text, "\r\n\r\n1234\r\n") {
		t.Fatalf("metadata-only mutation changed file bytes or identity: %s", text)
	}
}

func TestAdvancedDiscoveryAndDynamicRules(t *testing.T) {
	raw := "POST /api/users/550e8400-e29b-41d4-a716-446655440000?blob=eyJ1c2VyIjp7ImlkIjoiNyJ9fQ== HTTP/1.1\r\n" +
		"Host: bank.test\r\nContent-Type: application/json\r\nCookie: theme=dark; JSESSIONID=secret\r\nX-Original-URL: /admin\r\n\r\n" +
		`{"account":{"id":"1"}}`
	request, err := Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	points := DiscoverAdvanced(request, cfg)
	locations := map[string]bool{}
	var base64Point InsertionPoint
	for _, point := range points {
		locations[point.Location] = true
		if point.Location == "base64_json" {
			base64Point = point
		}
	}
	for _, location := range []string{"path", "cookie", "header", "base64_json", "json"} {
		if !locations[location] {
			t.Fatalf("advanced discovery missing %s: %#v", location, points)
		}
	}
	base64Mutated, err := Mutate(request, base64Point, "99")
	if err != nil || !strings.Contains(base64Mutated.Target, "blob=") || base64Mutated.Target == request.Target {
		t.Fatalf("nested Base64 JSON mutation failed: err=%v target=%s", err, base64Mutated.Target)
	}
	transformed, err := ApplyRequestTransforms(request, []config.RequestTransform{
		{Name: "签名", Algorithm: "hmac-sha256", Source: "literal:payload", Destination: "Header:X-Sign", Secret: "secret"},
		{Name: "时间", Algorithm: "timestamp", Destination: "query:ts"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if transformed.Header("X-Sign") == "" || !strings.Contains(transformed.Target, "ts=") {
		t.Fatalf("dynamic transform was not applied: %s", transformed.Raw(false))
	}
	response := model.Response{Headers: map[string]string{"x-csrf-token": "next-token"}, Body: []byte(`{"token":"body-token"}`)}
	refreshed, applied := ApplyResponseExtractors(transformed, response, []config.ResponseExtractor{
		{Name: "刷新 CSRF", Source: "Header:X-CSRF-Token", Pattern: `(.+)`, Destination: "header:X-CSRF-Token"},
	})
	if len(applied) != 1 || refreshed.Header("X-CSRF-Token") != "next-token" {
		t.Fatalf("response extractor failed: applied=%#v request=%s", applied, refreshed.Raw(false))
	}
}

func TestV23NestedDocumentsAndExcludedParameters(t *testing.T) {
	raw := "POST /api?nested=%7B%22user%22%3A%7B%22id%22%3A%227%22%7D%7D&content_string=ignored HTTP/1.1\r\n" +
		"Host: bank.test\r\nContent-Type: application/json\r\nX-Scan: {\"role\":\"user\"}\r\n\r\n" +
		`{"wrapper":"<root><id>7</id></root>","content_string":{"id":"must-not-scan"},"items":[{"name":"alice"}]}`
	request, err := Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.ScanHeaderNames = []string{"X-Scan"}
	cfg.ExcludedParameterNames = []string{"content_string"}
	points := DiscoverAdvanced(request, cfg)
	var queryJSON, bodyXML, headerJSON *InsertionPoint
	for index := range points {
		point := &points[index]
		if strings.Contains(point.Path, "content_string") || strings.EqualFold(point.Name, "content_string") {
			t.Fatalf("excluded parameter leaked into insertion points: %#v", *point)
		}
		switch {
		case point.Location == "nested_json" && strings.HasPrefix(point.Path, "nested"):
			queryJSON = point
		case point.Location == "nested_xml" && strings.HasPrefix(point.Path, "wrapper"):
			bodyXML = point
		case point.Location == "nested_json" && strings.HasPrefix(point.Path, "X-Scan"):
			headerJSON = point
		}
	}
	if queryJSON == nil || bodyXML == nil || headerJSON == nil {
		t.Fatalf("nested JSON/XML/header discovery incomplete: %#v", points)
	}
	mutatedQuery, err := Mutate(request, *queryJSON, "99")
	if err != nil || !strings.Contains(mutatedQuery.Target, "%2299%22") {
		t.Fatalf("nested query JSON mutation failed: err=%v target=%q", err, mutatedQuery.Target)
	}
	mutatedXML, err := Mutate(request, *bodyXML, "99")
	if err != nil || !strings.Contains(string(mutatedXML.Body), "&lt;") && !strings.Contains(string(mutatedXML.Body), ">99<") {
		t.Fatalf("nested XML mutation failed: err=%v body=%q", err, mutatedXML.Body)
	}
	mutatedHeader, err := Mutate(request, *headerJSON, "admin")
	if err != nil || !strings.Contains(mutatedHeader.Header("X-Scan"), `"admin"`) {
		t.Fatalf("nested header JSON mutation failed: err=%v header=%q", err, mutatedHeader.Header("X-Scan"))
	}
}

func TestTransformRegexpCacheIsBounded(t *testing.T) {
	request, err := Parse("GET / HTTP/1.1\r\nHost: bank.test\r\nX-Input: value\r\n\r\n", "https")
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < maxTransformRegexps+20; index++ {
		_, err := ApplyRequestTransforms(request, []config.RequestTransform{{
			Name: "bounded", Algorithm: "regex_replace", Source: "header:X-Input",
			Destination: "header:X-Output", Pattern: "value|never" + strings.Repeat("x", index), Replacement: "ok",
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	transformRegexps.Lock()
	count := len(transformRegexps.items)
	transformRegexps.Unlock()
	if count > maxTransformRegexps {
		t.Fatalf("transform regexp cache grew past bound: %d", count)
	}
}

func FuzzParseAndDiscoverAdvanced(f *testing.F) {
	f.Add("GET /?id=1 HTTP/1.1\r\nHost: example.test\r\n\r\n")
	f.Add("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"items\":[{\"id\":1}]}")
	f.Fuzz(func(t *testing.T, raw string) {
		request, err := Parse(raw, "https")
		if err != nil {
			return
		}
		_ = DiscoverAdvanced(request, config.Default())
	})
}

func TestParsePreservesValidMultipartAndRepairsBrowserPastedLF(t *testing.T) {
	body := "--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"safe.txt\"\r\n" +
		"Content-Type: text/plain\r\n\r\nline1\r\nline2\r\n--abc--\r\n"
	raw := "POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=abc\r\n\r\n" + body
	preserved, err := Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	if string(preserved.Body) != body {
		t.Fatalf("valid multipart body was altered:\nwant=%q\n got=%q", body, preserved.Body)
	}

	pasted := strings.ReplaceAll(raw, "\r\n", "\n")
	repaired, err := Parse(pasted, "https")
	if err != nil {
		t.Fatal(err)
	}
	text := string(repaired.Body)
	if !strings.Contains(text, "--abc\r\nContent-Disposition:") ||
		!strings.Contains(text, "\r\n\r\nline1\nline2\r\n--abc--\r\n") {
		t.Fatalf("pasted LF multipart framing was not rebuilt without rewriting file content: %q", text)
	}
}

func TestDynamicDestinationsPreserveUnrelatedWireContent(t *testing.T) {
	t.Run("query-json-cookie-form", func(t *testing.T) {
		raw := "POST /pay?z=last&token=old&a=first HTTP/1.1\r\nHost: bank.test\r\nCookie: theme=light; SESSION=old\r\nContent-Type: application/json\r\n\r\n{\n  \"huge\": 900719925474099312345, \"nested\": {\"token\": \"old\"}\n}"
		request, err := Parse(raw, "https")
		if err != nil {
			t.Fatal(err)
		}
		updated, err := ApplyDestinationValues(request, map[string]string{
			"query:token": "new query", "json:nested.token": "new-json", "cookie:SESSION": "new-cookie",
		})
		if err != nil {
			t.Fatal(err)
		}
		if updated.Target != "/pay?z=last&token=new+query&a=first" || !strings.Contains(string(updated.Body), "900719925474099312345") ||
			!strings.Contains(string(updated.Body), `"token": "new-json"`) || updated.Header("Cookie") != "theme=light; SESSION=new-cookie" {
			t.Fatalf("destination update altered unrelated content:\n%s", updated.Raw(false))
		}

		form, err := Parse("POST /form HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nz=last&csrf=old&a=first", "https")
		if err != nil {
			t.Fatal(err)
		}
		form, err = ApplyDestinationValues(form, map[string]string{"form:csrf": "new form"})
		if err != nil || string(form.Body) != "z=last&csrf=new+form&a=first" {
			t.Fatalf("form destination failed: err=%v body=%q", err, form.Body)
		}
	})

	t.Run("multipart", func(t *testing.T) {
		body := "--abc\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\nold\r\n--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"safe.txt\"\r\nContent-Type: text/plain\r\n\r\nunchanged-file\r\n--abc--\r\n"
		request, err := Parse("POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=abc\r\n\r\n"+body, "https")
		if err != nil {
			t.Fatal(err)
		}
		updated, err := ApplyDestinationValues(request, map[string]string{"multipart:csrf": "next-token"})
		if err != nil || !strings.Contains(string(updated.Body), "next-token") || !strings.Contains(string(updated.Body), "unchanged-file") {
			t.Fatalf("multipart destination failed: err=%v body=%q", err, updated.Body)
		}
	})
}

func TestV131ParameterMutationHelpers(t *testing.T) {
	t.Run("duplicate-query-order", func(t *testing.T) {
		request, err := Parse("GET /search?id=1&name=a HTTP/1.1\r\nHost: bank.test\r\n\r\n", "http")
		if err != nil {
			t.Fatal(err)
		}
		point := Discover(request, false)[0]
		mutated, err := DuplicateParameter(request, point, "bad", "1")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(mutated.Target, "id=bad&id=1") {
			t.Fatalf("duplicate order not preserved: %s", mutated.Target)
		}
	})

	t.Run("append-multipart-field-preserves-file", func(t *testing.T) {
		raw := "POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=AaB03x\r\n\r\n--AaB03x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nline1\r\nline2\r\n--AaB03x--\r\n"
		request, err := Parse(raw, "http")
		if err != nil {
			t.Fatal(err)
		}
		mutated, err := AddParameter(request, "multipart", "_method", "DELETE")
		if err != nil {
			t.Fatal(err)
		}
		body := string(mutated.Body)
		if !strings.Contains(body, "line1\r\nline2") || !strings.Contains(body, `name="_method"`) || !strings.Contains(body, "\r\n\r\nDELETE\r\n--AaB03x--") {
			t.Fatalf("multipart append corrupted body:\n%s", body)
		}
	})

	t.Run("nested-array-session-points", func(t *testing.T) {
		request, err := Parse("POST /batch HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n[{\"user\":{\"sessionId\":\"secret\"}}]", "http")
		if err != nil {
			t.Fatal(err)
		}
		points := SessionPoints(request, config.SessionKeyList{"sessionId"})
		if len(points) != 1 || points[0].Path != "[0].user.sessionId" {
			t.Fatalf("nested array session not discovered: %#v", points)
		}
	})
}

func TestV24JSONSuffixSniffAndXMLAttributeMutation(t *testing.T) {
	for _, contentType := range []string{"application/problem+json", "application/octet-stream"} {
		request, err := Parse("POST /api HTTP/1.1\r\nHost: bank.test\r\nContent-Type: "+contentType+"\r\n\r\n{\"id\":731}", "http")
		if err != nil {
			t.Fatal(err)
		}
		points := Discover(request, false)
		if len(points) != 1 || points[0].Name != "id" || points[0].ValueType != "number" {
			t.Fatalf("JSON body was not discovered for %s: %#v", contentType, points)
		}
	}

	request, err := Parse("POST /xml HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/xml\r\n\r\n<query value=\"safe\"/>", "http")
	if err != nil {
		t.Fatal(err)
	}
	var attribute *InsertionPoint
	for _, point := range Discover(request, false) {
		if point.Location == "xml_attribute" && point.Name == "value" {
			copyPoint := point
			attribute = &copyPoint
			break
		}
	}
	if attribute == nil {
		t.Fatal("XML attribute insertion point was not discovered")
	}
	mutated, err := Mutate(request, *attribute, `x" AND 731=731`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mutated.Body), `value="x&quot; AND 731=731"`) {
		t.Fatalf("XML attribute payload was not escaped precisely: %s", mutated.Body)
	}
}
