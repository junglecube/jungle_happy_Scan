package plugin

import (
	"jungle_happy_Scan/internal/model"
	"time"
)

// Settle on every return path, including timeout and budget exhaustion. Each
// batch has at most one bounded late observer, tied to the task context.
func settleOAST(ctx *Context, tokens []string, build func(string, bool) model.Finding) []model.Finding {
	if len(tokens) == 0 {
		return nil
	}
	hits := waitCallbackBatch(ctx.Context, ctx.Callbacks, tokens, time.Duration(ctx.Config.CallbackWaitSeconds)*time.Second)
	var findings []model.Finding
	var pending []string
	for _, token := range tokens {
		if hits[token] {
			findings = append(findings, build(token, false))
		} else {
			pending = append(pending, token)
		}
	}
	if len(pending) == 0 || ctx.OnLateFindings == nil || ctx.Config.CallbackLateSeconds <= 0 || ctx.Context.Err() != nil {
		return findings
	}
	if ctx.OnCallbackPending != nil {
		ctx.OnCallbackPending(1)
	}
	go func() {
		if ctx.OnCallbackPending != nil {
			defer ctx.OnCallbackPending(-1)
		}
		deadline := time.NewTimer(time.Duration(ctx.Config.CallbackLateSeconds) * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Context.Done():
				return
			case <-deadline.C:
				return
			case <-ticker.C:
				hits := waitCallbackBatch(ctx.Context, ctx.Callbacks, pending, 0)
				rest := pending[:0]
				var added []model.Finding
				for _, token := range pending {
					if hits[token] {
						added = append(added, build(token, true))
					} else {
						rest = append(rest, token)
					}
				}
				pending = rest
				if len(added) > 0 {
					ctx.OnLateFindings(added)
				}
				if len(pending) == 0 {
					return
				}
			}
		}
	}()
	return findings
}
