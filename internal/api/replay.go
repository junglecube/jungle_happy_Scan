package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/engine"
	"jungle_happy_Scan/internal/model"
)

const (
	replayDetailLimit = 200_000
	replayListMaxPage = 200
)

type replayCreateRequest struct {
	model.ScanInput
	Concurrency int      `json:"concurrency,omitempty"`
	Repeat      int      `json:"repeat,omitempty"`
	MaxRequests int      `json:"max_requests,omitempty"`
	Dictionary  []string `json:"dictionary,omitempty"`
}

type replayTask struct {
	mu          sync.RWMutex
	id          string
	status      string
	error       string
	createdAt   time.Time
	startedAt   *time.Time
	finishedAt  *time.Time
	total       int
	completed   int
	failed      int
	truncated   bool
	concurrency int
	cancel      context.CancelFunc
	results     []replayResultSummary
	details     map[string]replayResultDetail
}

type replayResultSummary struct {
	ID                string `json:"id"`
	Index             int    `json:"index"`
	Payload           string `json:"payload"`
	StatusCode        int    `json:"status_code,omitempty"`
	ResponseBytes     int64  `json:"response_bytes"`
	CapturedBytes     int    `json:"captured_bytes"`
	ElapsedMS         int64  `json:"elapsed_ms"`
	Scheme            string `json:"scheme,omitempty"`
	Error             string `json:"error,omitempty"`
	ResponseTruncated bool   `json:"response_truncated,omitempty"`
}

type replayResultDetail struct {
	replayResultSummary
	RawResponse string `json:"raw_response,omitempty"`
}

func (s *Server) replayCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.createReplay(w, r)
	case http.MethodGet:
		s.listReplays(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "只支持 GET 或 POST")
	}
}

func (s *Server) replayRoute(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/replays/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "重放任务不存在")
		return
	}
	task, ok := s.getReplay(parts[0])
	if !ok {
		writeError(w, http.StatusNotFound, "重放任务不存在")
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		s.writeReplaySnapshot(w, r, task)
	case len(parts) == 1 && r.Method == http.MethodDelete:
		task.cancelTask()
		writeJSON(w, http.StatusAccepted, map[string]any{"replay_id": task.id, "status": "cancelling"})
	case len(parts) == 3 && parts[1] == "results" && r.Method == http.MethodGet:
		task.writeDetail(w, parts[2])
	default:
		writeError(w, http.StatusNotFound, "重放接口不存在")
	}
}

func (s *Server) createReplay(w http.ResponseWriter, r *http.Request) {
	var input replayCreateRequest
	if err := decodeJSON(w, r, &input, 8_000_000); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.HTTP == "" {
		input.HTTP = input.HTTPRequest
	}
	if strings.TrimSpace(input.HTTP) == "" {
		writeError(w, http.StatusBadRequest, "http 字段不能为空")
		return
	}
	if input.Concurrency == 0 {
		input.Concurrency = 10
	}
	if input.MaxRequests == 0 {
		input.MaxRequests = 10_000
	}
	variants, truncated, err := engine.ExpandReplayTemplate(input.HTTP, engine.ReplayOptions{
		Repeat: input.Repeat, MaxRequests: input.MaxRequests, Dictionary: input.Dictionary,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if input.Concurrency < 1 || input.Concurrency > engine.MaxReplayConcurrency {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("concurrency 必须在 1 到 %d 之间", engine.MaxReplayConcurrency))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	task := &replayTask{
		id: newReplayID(), status: "queued", createdAt: time.Now().UTC(), total: len(variants),
		truncated: truncated, concurrency: input.Concurrency, cancel: cancel, details: make(map[string]replayResultDetail),
	}
	s.replayMu.Lock()
	s.replays[task.id] = task
	s.replayMu.Unlock()
	go s.runReplayTask(ctx, task, input.ScanInput, variants, input.Concurrency)
	task.mu.RLock()
	status, total, truncated, taskConcurrency := task.status, task.total, task.truncated, task.concurrency
	task.mu.RUnlock()
	writeJSON(w, http.StatusAccepted, map[string]any{
		"replay_id": task.id, "status": status, "total": total,
		"truncated": truncated, "concurrency": taskConcurrency,
	})
}

func (s *Server) runReplayTask(ctx context.Context, task *replayTask, input model.ScanInput, variants []engine.ReplayVariant, concurrency int) {
	task.markRunning()
	err := s.manager.RunReplayVariants(ctx, input, variants, concurrency, func(result engine.ReplayResult) {
		task.addResult(result)
	})
	task.finish(err)
}

func (s *Server) listReplays(w http.ResponseWriter, _ *http.Request) {
	s.replayMu.RLock()
	items := make([]map[string]any, 0, len(s.replays))
	for _, task := range s.replays {
		items = append(items, task.summary())
	}
	s.replayMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"replays": items})
}

func (s *Server) writeReplaySnapshot(w http.ResponseWriter, r *http.Request, task *replayTask) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > replayListMaxPage {
		pageSize = replayListMaxPage
	}
	writeJSON(w, http.StatusOK, task.snapshot(page, pageSize))
}

func (s *Server) getReplay(id string) (*replayTask, bool) {
	s.replayMu.RLock()
	defer s.replayMu.RUnlock()
	task, ok := s.replays[id]
	return task, ok
}

func (s *Server) closeReplays() {
	s.replayMu.RLock()
	tasks := make([]*replayTask, 0, len(s.replays))
	for _, task := range s.replays {
		tasks = append(tasks, task)
	}
	s.replayMu.RUnlock()
	for _, task := range tasks {
		task.cancelTask()
	}
}

func (t *replayTask) markRunning() {
	now := time.Now().UTC()
	t.mu.Lock()
	t.status = "running"
	t.startedAt = &now
	t.mu.Unlock()
}

func (t *replayTask) addResult(result engine.ReplayResult) {
	id := fmt.Sprintf("result_%d", result.Index)
	summary := replayResultSummary{
		ID: id, Index: result.Index, Payload: result.Payload, StatusCode: result.StatusCode,
		ResponseBytes: result.ResponseBytes, CapturedBytes: result.CapturedBytes, ElapsedMS: result.ElapsedMS,
		Scheme: result.Scheme, Error: result.Error, ResponseTruncated: result.ResponseTruncated,
	}
	raw := result.RawResponse
	if len(raw) > replayDetailLimit {
		raw = raw[:replayDetailLimit] + "\n...[response truncated at 200000 bytes]"
		summary.ResponseTruncated = true
	}
	t.mu.Lock()
	t.completed++
	if result.Error != "" {
		t.failed++
	}
	t.results = append(t.results, summary)
	t.details[id] = replayResultDetail{replayResultSummary: summary, RawResponse: raw}
	t.mu.Unlock()
}

func (t *replayTask) finish(err error) {
	now := time.Now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.finishedAt = &now
	if err != nil {
		if errorsIsCanceled(err) {
			t.status = "cancelled"
		} else {
			t.status = "failed"
			t.error = err.Error()
		}
		return
	}
	t.status = "completed"
}

func (t *replayTask) cancelTask() {
	t.mu.RLock()
	cancel := t.cancel
	t.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

func (t *replayTask) summary() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return map[string]any{
		"replay_id": t.id, "status": t.status, "created_at": t.createdAt,
		"total": t.total, "completed": t.completed, "failed": t.failed,
		"truncated": t.truncated, "concurrency": t.concurrency, "error": t.error,
	}
}

func (t *replayTask) snapshot(page, pageSize int) map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	start := (page - 1) * pageSize
	if start > len(t.results) {
		start = len(t.results)
	}
	end := min(start+pageSize, len(t.results))
	elapsed := int64(0)
	if t.startedAt != nil {
		until := time.Now().UTC()
		if t.finishedAt != nil {
			until = *t.finishedAt
		}
		elapsed = until.Sub(*t.startedAt).Milliseconds()
	}
	return map[string]any{
		"replay_id": t.id, "status": t.status, "error": t.error, "total": t.total,
		"completed": t.completed, "failed": t.failed, "truncated": t.truncated,
		"concurrency": t.concurrency, "elapsed_ms": elapsed,
		"page": page, "page_size": pageSize, "result_count": len(t.results),
		"results": append([]replayResultSummary(nil), t.results[start:end]...),
	}
}

func (t *replayTask) writeDetail(w http.ResponseWriter, id string) {
	t.mu.RLock()
	detail, ok := t.details[id]
	t.mu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, "重放结果不存在")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": detail})
}

func newReplayID() string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return "replay_" + hex.EncodeToString(raw)
}

func errorsIsCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}
