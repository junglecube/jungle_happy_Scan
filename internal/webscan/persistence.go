package webscan

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/model"
)

const persistenceVersion = 1

type persistedSession struct {
	Version          int           `json:"version"`
	SavedAt          time.Time     `json:"saved_at"`
	ID               string        `json:"id"`
	Config           SessionConfig `json:"config"`
	Status           string        `json:"status"`
	CreatedAt        time.Time     `json:"created_at"`
	LastError        string        `json:"last_error,omitempty"`
	GlobalScope      bool          `json:"global_scope"`
	Revision         uint64        `json:"revision"`
	AssetRevision    uint64        `json:"asset_revision,omitempty"`
	ProgressRevision uint64        `json:"progress_revision,omitempty"`
	FindingRevision  uint64        `json:"finding_revision,omitempty"`
	Observed         int           `json:"observed_requests"`
	Tunnels          int           `json:"https_tunnels"`
	AssetIDs         []string      `json:"asset_ids"`
}

type persistedAsset struct {
	Version  int            `json:"version"`
	SavedAt  time.Time      `json:"saved_at"`
	Asset    Asset          `json:"asset"`
	Baseline model.Response `json:"baseline"`
}

type persistenceKey struct {
	sessionID string
	assetID   string
}

type persistenceStore struct {
	dir     string
	logger  *slog.Logger
	manager *Manager
	mu      sync.Mutex
	dirty   map[string]persistenceKey
	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
}

func newPersistenceStore(dir string, logger *slog.Logger, manager *Manager) *persistenceStore {
	store := &persistenceStore{
		dir: dir, logger: logger, manager: manager, dirty: make(map[string]persistenceKey),
		wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		logger.Error("WEB scan recovery directory unavailable", "directory", dir, "error", err)
		return nil
	}
	go store.loop()
	return store
}

func (p *persistenceStore) mark(key persistenceKey) {
	if p == nil || key.sessionID == "" {
		return
	}
	mapKey := key.sessionID + "\x00" + key.assetID
	p.mu.Lock()
	p.dirty[mapKey] = key
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *persistenceStore) loop() {
	defer close(p.done)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	pending := false
	for {
		select {
		case <-p.wake:
			if !pending {
				timer.Reset(400 * time.Millisecond)
				pending = true
			}
		case <-timer.C:
			p.flushDirty()
			pending = false
		case <-p.stop:
			if pending && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			p.flushDirty()
			return
		}
	}
}

func (p *persistenceStore) flushDirty() {
	p.mu.Lock()
	dirty := p.dirty
	p.dirty = make(map[string]persistenceKey)
	p.mu.Unlock()
	for _, key := range dirty {
		if key.assetID == "" {
			p.writeSession(p.manager, key.sessionID)
		} else {
			p.writeAsset(p.manager, key.sessionID, key.assetID)
		}
	}
}

func (m *Manager) markSessionDirty(sessionID string) {
	if m.persistence != nil {
		m.persistence.mark(persistenceKey{sessionID: sessionID})
	}
}

func (m *Manager) markAssetDirty(sessionID, assetID string) {
	if m.persistence != nil {
		m.persistence.mark(persistenceKey{sessionID: sessionID, assetID: assetID})
		m.persistence.mark(persistenceKey{sessionID: sessionID})
	}
}

func (m *Manager) removePersisted(sessionID string) {
	if m.persistence == nil || sessionID == "" {
		return
	}
	_ = os.RemoveAll(filepath.Join(m.persistence.dir, sessionID))
}

func (p *persistenceStore) clearAssets(sessionID string) {
	if p == nil || sessionID == "" {
		return
	}
	p.mu.Lock()
	for key, value := range p.dirty {
		if value.sessionID == sessionID && value.assetID != "" {
			delete(p.dirty, key)
		}
	}
	p.mu.Unlock()
	if err := os.RemoveAll(filepath.Join(p.dir, sessionID, "assets")); err != nil {
		p.logger.Error("clear WEB scan persisted assets failed", "session_id", sessionID, "error", err)
	}
}

func (p *persistenceStore) writeSession(manager *Manager, sessionID string) {
	session, ok := manager.session(sessionID)
	if !ok {
		return
	}
	session.mu.RLock()
	snapshot := persistedSession{
		Version: persistenceVersion, SavedAt: time.Now().UTC(), ID: session.id,
		Config: session.cfg, Status: session.status, CreatedAt: session.created,
		LastError: session.lastErr, GlobalScope: session.globalScope,
		Revision: session.revision, AssetRevision: session.assetRevision,
		ProgressRevision: session.progressRevision, FindingRevision: session.findingRevision,
		Observed: session.observed, Tunnels: session.tunnels,
	}
	for _, fingerprint := range session.order {
		if asset := session.assets[fingerprint]; asset != nil {
			snapshot.AssetIDs = append(snapshot.AssetIDs, asset.ID)
		}
	}
	session.mu.RUnlock()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		p.logger.Error("serialize WEB scan session failed", "session_id", sessionID, "error", err)
		return
	}
	if err := atomicWrite(filepath.Join(p.dir, sessionID, "session.json"), append(data, '\n'), 0o600); err != nil {
		p.logger.Error("persist WEB scan session failed", "session_id", sessionID, "error", err)
	}
}

func (p *persistenceStore) writeAsset(manager *Manager, sessionID, assetID string) {
	session, ok := manager.session(sessionID)
	if !ok {
		return
	}
	session.mu.RLock()
	asset := session.assets[assetID]
	if asset == nil {
		session.mu.RUnlock()
		return
	}
	if asset.Cold {
		session.mu.RUnlock()
		return
	}
	cloned := asset.clone()
	baseline := asset.Baseline
	session.mu.RUnlock()
	snapshot := persistedAsset{
		Version: persistenceVersion, SavedAt: time.Now().UTC(), Asset: cloned, Baseline: baseline,
	}
	path := filepath.Join(p.dir, sessionID, "assets", assetID+".json.gz")
	if err := atomicWriteGzip(path, snapshot); err != nil {
		p.logger.Error("persist WEB scan asset failed", "session_id", sessionID, "asset_id", assetID, "error", err)
		return
	}
	manager.coolAsset(sessionID, assetID)
}

func (p *persistenceStore) flushAll(manager *Manager) {
	manager.mu.RLock()
	sessions := make([]*Session, 0, len(manager.sessions))
	for _, session := range manager.sessions {
		sessions = append(sessions, session)
	}
	manager.mu.RUnlock()
	for _, session := range sessions {
		p.writeSession(manager, session.id)
		session.mu.RLock()
		ids := make([]string, 0, len(session.order))
		for _, fingerprint := range session.order {
			if asset := session.assets[fingerprint]; asset != nil {
				ids = append(ids, asset.ID)
			}
		}
		session.mu.RUnlock()
		for _, id := range ids {
			p.writeAsset(manager, session.id, id)
		}
		p.pruneAssets(session.id, ids)
	}
}

func (p *persistenceStore) pruneAssets(sessionID string, ids []string) {
	keep := make(map[string]bool, len(ids))
	for _, id := range ids {
		keep[id+".json.gz"] = true
	}
	files, _ := os.ReadDir(filepath.Join(p.dir, sessionID, "assets"))
	for _, file := range files {
		if !file.IsDir() && !keep[file.Name()] {
			_ = os.Remove(filepath.Join(p.dir, sessionID, "assets", file.Name()))
		}
	}
}

func (p *persistenceStore) close() {
	close(p.stop)
	<-p.done
}

func (m *Manager) restoreSessions() {
	if m.persistence == nil {
		return
	}
	entries, err := os.ReadDir(m.persistence.dir)
	if err != nil {
		m.logger.Error("read WEB scan recovery directory failed", "error", err)
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		session, err := m.persistence.readSession(entry.Name())
		if err != nil {
			m.logger.Warn("skip invalid WEB scan recovery", "session_id", entry.Name(), "error", err)
			continue
		}
		m.sessions[session.id] = session
	}
}

func (p *persistenceStore) readSession(sessionID string) (*Session, error) {
	data, err := readRecoveryFile(filepath.Join(p.dir, sessionID, "session.json"))
	if err != nil {
		return nil, err
	}
	var snapshot persistedSession
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Version != persistenceVersion || snapshot.ID == "" {
		return nil, errors.New("unsupported recovery snapshot")
	}
	scope := make(map[string]bool)
	if !snapshot.GlobalScope {
		for _, host := range snapshot.Config.ScopeHosts {
			scope[strings.ToLower(strings.TrimSuffix(host, "."))] = true
		}
	}
	snapshot.Config.BrowserOwner = ""
	session := &Session{
		cfg: snapshot.Config, id: snapshot.ID, status: "stopped", created: snapshot.CreatedAt,
		lastErr: snapshot.LastError, scope: scope, globalScope: snapshot.GlobalScope,
		allowOutOfScope: loopbackListen(snapshot.Config.ProxyListen),
		revision:        snapshot.Revision + 1, assetRevision: snapshot.AssetRevision + 1,
		progressRevision: snapshot.ProgressRevision + 1, findingRevision: snapshot.FindingRevision + 1,
		observed: snapshot.Observed, tunnels: snapshot.Tunnels,
		assets: make(map[string]*Asset), tunnelConns: make(map[net.Conn]net.Conn),
		interceptions: make(map[string]*interceptionItem), interceptRevision: 1, interceptChanged: make(chan struct{}),
	}
	for _, assetID := range snapshot.AssetIDs {
		assetFile := filepath.Join(p.dir, sessionID, "assets", assetID+".json.gz")
		var persisted persistedAsset
		if err := readGzipJSON(assetFile, &persisted); err != nil || persisted.Asset.ID == "" {
			continue
		}
		asset := persisted.Asset
		asset.Baseline = persisted.Baseline
		if asset.ScanStatus == "queued" || asset.ScanStatus == "scanning" || asset.ScanStatus == "running" {
			asset.ScanStatus = "failed"
			asset.Error = "HappyScan进程中断，未自动重放该扫描"
		}
		asset.RawRequest, asset.RawResponse = "", ""
		asset.Baseline = model.Response{}
		for index := range asset.Findings {
			asset.Findings[index].Evidence = nil
		}
		asset.Cold = true
		copy := asset
		session.assets[copy.ID] = &copy
		session.assets[copy.Fingerprint] = &copy
		session.order = append(session.order, copy.Fingerprint)
	}
	sort.Slice(session.order, func(i, j int) bool {
		return session.assets[session.order[i]].FirstSeen.Before(session.assets[session.order[j]].FirstSeen)
	})
	session.counters.ObservedRequests = session.observed
	session.counters.HTTPSTunnels = session.tunnels
	for _, fingerprint := range session.order {
		asset := session.assets[fingerprint]
		if asset == nil {
			continue
		}
		session.counters.Assets++
		session.counters.Findings += asset.FindingsCount
		adjustStatusCounter(&session.counters, asset.ScanStatus, 1)
	}
	return session, nil
}

func (p *persistenceStore) readAsset(sessionID, assetID string) (Asset, error) {
	var persisted persistedAsset
	path := filepath.Join(p.dir, sessionID, "assets", assetID+".json.gz")
	if err := readGzipJSON(path, &persisted); err != nil {
		return Asset{}, err
	}
	persisted.Asset.Baseline = persisted.Baseline
	persisted.Asset.Cold = false
	return persisted.Asset, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceFile(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func atomicWriteGzip(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".tmp-*.gz")
	if err != nil {
		return err
	}
	name := file.Name()
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	writer := gzip.NewWriter(file)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := replaceFile(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func readGzipJSON(path string, target any) error {
	file, err := openRecoveryFile(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := gzip.NewReader(io.LimitReader(file, 128_000_000))
	if err != nil {
		return err
	}
	defer reader.Close()
	return json.NewDecoder(io.LimitReader(reader, 120_000_000)).Decode(target)
}

func readRecoveryFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return data, err
	}
	return os.ReadFile(path + ".bak")
}

func openRecoveryFile(path string) (*os.File, error) {
	file, err := os.Open(path)
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		return file, err
	}
	return os.Open(path + ".bak")
}

func replaceFile(temporary, target string) error {
	if err := os.Rename(temporary, target); err == nil {
		return nil
	}
	backup := target + ".bak"
	_ = os.Remove(backup)
	if err := os.Rename(target, backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		_ = os.Rename(backup, target)
		return err
	}
	_ = os.Remove(backup)
	return nil
}
