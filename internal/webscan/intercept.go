package webscan

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	maxInterceptBytes   = 10_000_000
	maxInterceptHistory = 250
)

type InterceptionView struct {
	ID            string     `json:"id"`
	TransactionID string     `json:"transaction_id"`
	Direction     string     `json:"direction"`
	Status        string     `json:"status"`
	Method        string     `json:"method"`
	Host          string     `json:"host"`
	Path          string     `json:"path"`
	ContentType   string     `json:"content_type,omitempty"`
	Raw           string     `json:"raw"`
	Editable      bool       `json:"editable"`
	Modified      bool       `json:"modified"`
	BodyBytes     int64      `json:"body_bytes"`
	CreatedAt     time.Time  `json:"created_at"`
	Deadline      time.Time  `json:"deadline"`
	ResolvedAt    *time.Time `json:"resolved_at,omitempty"`
	Resolution    string     `json:"resolution,omitempty"`
	Reason        string     `json:"reason,omitempty"`
}

type interceptionItem struct {
	view     InterceptionView
	decision chan interceptDecision
	once     sync.Once
}

type interceptDecision struct {
	action string
	raw    string
}

type InterceptionSettings struct {
	InterceptRequests  bool `json:"intercept_requests"`
	InterceptResponses bool `json:"intercept_responses"`
}

func (m *Manager) Interceptions(sessionID string) ([]InterceptionView, bool) {
	session, ok := m.session(sessionID)
	if !ok {
		return nil, false
	}
	session.mu.RLock()
	result := make([]InterceptionView, 0, session.pendingIntercepts)
	for i := len(session.interceptOrder) - 1; i >= 0; i-- {
		if item := session.interceptions[session.interceptOrder[i]]; item != nil && item.view.Status == "pending" {
			summary := item.view
			summary.Raw = ""
			result = append(result, summary)
		}
	}
	session.mu.RUnlock()
	return result, true
}

// WaitInterceptions implements an event-driven long poll. It returns as soon
// as the pending queue changes and otherwise keeps an idle browser request
// open for at most wait. Raw messages remain available from the detail route.
func (m *Manager) WaitInterceptions(ctx context.Context, sessionID string, since uint64, wait time.Duration) ([]InterceptionView, uint64, bool) {
	session, ok := m.session(sessionID)
	if !ok {
		return nil, 0, false
	}
	if wait <= 0 || wait > 30*time.Second {
		wait = 25 * time.Second
	}
	session.mu.RLock()
	revision, changed := session.interceptRevision, session.interceptChanged
	session.mu.RUnlock()
	if since == revision && changed != nil {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, revision, true
		case <-timer.C:
		case <-changed:
		}
	}
	items, ok := m.Interceptions(sessionID)
	if !ok {
		return nil, 0, false
	}
	session.mu.RLock()
	revision = session.interceptRevision
	session.mu.RUnlock()
	return items, revision, true
}

func (m *Manager) Interception(sessionID, interceptionID string) (InterceptionView, bool) {
	session, ok := m.session(sessionID)
	if !ok {
		return InterceptionView{}, false
	}
	session.mu.RLock()
	item := session.interceptions[interceptionID]
	if item == nil {
		session.mu.RUnlock()
		return InterceptionView{}, false
	}
	result := item.view
	session.mu.RUnlock()
	return result, true
}

func (m *Manager) Decide(sessionID, interceptionID, action, raw string) error {
	session, ok := m.session(sessionID)
	if !ok {
		return errors.New("WEB扫描任务不存在")
	}
	action = strings.ToLower(strings.TrimSpace(action))
	if action != "forward" && action != "drop" {
		return errors.New("action 必须是 forward 或 drop")
	}
	session.mu.RLock()
	item := session.interceptions[interceptionID]
	if item == nil {
		session.mu.RUnlock()
		return errors.New("拦截项不存在")
	}
	if item.view.Status != "pending" {
		session.mu.RUnlock()
		return errors.New("拦截项已经处理")
	}
	if raw != "" && !item.view.Editable {
		session.mu.RUnlock()
		return errors.New("该报文不可安全编辑，只能原样放行或丢弃")
	}
	session.mu.RUnlock()
	item.once.Do(func() { item.decision <- interceptDecision{action: action, raw: raw} })
	return nil
}

func (m *Manager) UpdateInterception(sessionID string, settings InterceptionSettings) (SessionView, error) {
	session, ok := m.session(sessionID)
	if !ok {
		return SessionView{}, errors.New("WEB扫描任务不存在")
	}
	session.mu.Lock()
	session.cfg.InterceptRequests = settings.InterceptRequests
	session.cfg.InterceptResponses = settings.InterceptResponses
	session.revision++
	session.signalInterceptionLocked()
	var release []*interceptionItem
	for _, item := range session.interceptions {
		if item.view.Status == "pending" &&
			(item.view.Direction == "request" && !settings.InterceptRequests ||
				item.view.Direction == "response" && !settings.InterceptResponses) {
			release = append(release, item)
		}
	}
	session.mu.Unlock()
	for _, item := range release {
		item.once.Do(func() { item.decision <- interceptDecision{action: "forward"} })
	}
	m.markSessionDirty(sessionID)
	return session.view(false), nil
}

func (s *Session) awaitInterception(ctx context.Context, direction, transactionID, raw, method, host, path, contentType string, bodyBytes int64, editable bool) (interceptDecision, bool) {
	s.mu.Lock()
	enabled := direction == "request" && s.cfg.InterceptRequests || direction == "response" && s.cfg.InterceptResponses
	if !enabled || s.status != "listening" || s.pendingIntercepts >= s.cfg.MaxPendingIntercepts {
		s.mu.Unlock()
		return interceptDecision{action: "forward"}, false
	}
	now := time.Now().UTC()
	item := &interceptionItem{
		view: InterceptionView{
			ID: newID("intercept"), TransactionID: transactionID, Direction: direction,
			Status: "pending", Method: method, Host: host, Path: path, ContentType: contentType,
			Raw: raw, Editable: editable, BodyBytes: bodyBytes, CreatedAt: now,
			Deadline: now.Add(time.Duration(s.cfg.InterceptTimeout) * time.Second),
		},
		decision: make(chan interceptDecision, 1),
	}
	s.interceptions[item.view.ID] = item
	s.interceptOrder = append(s.interceptOrder, item.view.ID)
	s.pendingIntercepts++
	s.signalInterceptionLocked()
	s.trimInterceptionHistoryLocked()
	timeout := time.Duration(s.cfg.InterceptTimeout) * time.Second
	timeoutAction := s.cfg.InterceptOnTimeout
	s.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	decision := interceptDecision{action: "forward"}
	status, reason := "forwarded", ""
	select {
	case decision = <-item.decision:
		if decision.action == "drop" {
			status = "dropped"
		} else if decision.raw != "" && decision.raw != raw {
			status = "modified"
		}
	case <-timer.C:
		decision.action = timeoutAction
		status, reason = "timed_out", "等待人工处理超时，已执行默认动作"
	case <-ctx.Done():
		status, reason = "cancelled", "客户端连接已关闭"
	}
	resolved := time.Now().UTC()
	s.mu.Lock()
	if item.view.Status == "pending" {
		item.view.Status = status
		item.view.Resolution = decision.action
		item.view.Modified = decision.raw != "" && decision.raw != raw
		item.view.Reason = reason
		item.view.ResolvedAt = &resolved
		if s.pendingIntercepts > 0 {
			s.pendingIntercepts--
		}
		s.signalInterceptionLocked()
	}
	s.mu.Unlock()
	return decision, true
}

func (s *Session) signalInterceptionLocked() {
	s.interceptRevision++
	if s.interceptChanged != nil {
		close(s.interceptChanged)
	}
	s.interceptChanged = make(chan struct{})
}

func (s *Session) releasePendingInterceptions(reason string) {
	s.mu.RLock()
	items := make([]*interceptionItem, 0, s.pendingIntercepts)
	for _, item := range s.interceptions {
		if item.view.Status == "pending" {
			items = append(items, item)
		}
	}
	s.mu.RUnlock()
	for _, item := range items {
		item.once.Do(func() { item.decision <- interceptDecision{action: "forward"} })
	}
}

func (s *Session) trimInterceptionHistoryLocked() {
	for len(s.interceptOrder) > maxInterceptHistory {
		index := -1
		for i, id := range s.interceptOrder {
			if item := s.interceptions[id]; item != nil && item.view.Status != "pending" {
				index = i
				break
			}
		}
		if index < 0 {
			return
		}
		delete(s.interceptions, s.interceptOrder[index])
		s.interceptOrder = append(s.interceptOrder[:index], s.interceptOrder[index+1:]...)
	}
}
