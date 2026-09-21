package plugin

import (
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
)

func TestParameterCandidatesFollowPluginSemantics(t *testing.T) {
	request, err := httpraw.Parse("GET /sms/send?phonekey=13800138000&id=7 HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=secret\r\n\r\n", "https")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	points := httpraw.DiscoverAdvanced(request, cfg)
	sms := ParameterCandidates(SMSAbuse{}, request, points, cfg)
	if len(sms) != 1 || sms[0].Name != "phonekey" {
		t.Fatalf("SMS candidates should use controlled semantic matching: %#v", sms)
	}
	sql := ParameterCandidates(SQLInjection{}, request, points, cfg)
	for _, item := range sql {
		if item.Location == "cookie" || item.Location == "header" {
			t.Fatalf("SQL candidate leaked ambient credential: %#v", item)
		}
	}
	if len(sql) != 2 {
		t.Fatalf("SQL candidates should include query points: %#v", sql)
	}
}

func TestFileUploadCandidatesAndScope(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=JHS\r\n\r\n--JHS\r\nContent-Disposition: form-data; name=avatar; filename=photo.jpg\r\nContent-Type: image/jpeg\r\n\r\nbytes\r\n--JHS--\r\n"
	request, err := httpraw.Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	points := httpraw.DiscoverAdvanced(request, cfg)
	candidates := ParameterCandidates(FileUpload{}, request, points, cfg)
	if len(candidates) != 1 || candidates[0].Name != "avatar" {
		t.Fatalf("unexpected upload candidates: %#v", candidates)
	}
	if len(ScopedMultipartFiles(request, []string{"other"})) != 0 || len(ScopedMultipartFiles(request, []string{"avatar"})) != 1 {
		t.Fatal("multipart scope was not applied")
	}
}
