package plugin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"jungle_happy_Scan/internal/model"
)

type JWTWeak struct{}

func (JWTWeak) Meta() model.PluginMeta {
	return PassiveMeta("jwt_weak", "JWT 弱配置", "只解析 JWT，检查 none 算法、缺少过期时间、超长有效期和敏感声明。")
}

func (p JWTWeak) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	ctx.Progress(meta.ID, 1, 1)
	var findings []model.Finding
	for _, candidate := range jwtCandidates(ctx.Request, ctx.Points) {
		token := candidate.raw
		parts := strings.Split(token, ".")
		if len(parts) != 3 || !strings.HasPrefix(parts[0], "eyJ") {
			continue
		}
		var jwtHeader, payload map[string]any
		if decodeJWT(parts[0], &jwtHeader) != nil || decodeJWT(parts[1], &payload) != nil {
			continue
		}
		var problems []string
		if strings.EqualFold(fmt.Sprint(jwtHeader["alg"]), "none") {
			problems = append(problems, "alg=none")
		}
		exp, exists := payload["exp"]
		if !exists {
			problems = append(problems, "缺少 exp")
		} else if value, ok := exp.(float64); ok && time.Unix(int64(value), 0).After(time.Now().Add(30*24*time.Hour)) {
			problems = append(problems, "有效期超过 30 天")
		}
		for key := range payload {
			switch strings.ToLower(key) {
			case "password", "passwd", "secret", "idcard", "bankcard":
				problems = append(problems, "包含敏感声明 "+key)
			}
		}
		if len(problems) == 0 {
			continue
		}
		severity := model.SeverityMedium
		if contains(problems, "alg=none") {
			severity = model.SeverityHigh
		}
		findings = append(findings, Finding(meta, "JWT 存在弱配置", severity, model.ConfidenceCertain, candidate.affected,
			strings.Join(problems, "；")+"。插件不会尝试伪造签名。",
			"固定允许的强签名算法；验证 issuer/audience/exp/nbf；缩短有效期且不要在 JWT 中放置敏感信息。",
			[]model.Evidence{ctx.Evidence("JWT Header 和 Claims 显示弱配置", nil, nil, map[string]any{"problems": problems})}))
	}
	return findings, nil
}

func decodeJWT(segment string, target any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
