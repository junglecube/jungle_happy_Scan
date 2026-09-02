package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"jungle_happy_Scan/internal/api"
	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/engine"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	configPath := flag.String("config", "./config/config.json", "配置文件路径")
	listenOverride := flag.String("listen", "", "临时覆盖监听地址")
	showVersion := flag.Bool("version", false, "显示版本")
	flag.Parse()
	if *showVersion {
		fmt.Printf("jungle_happy_Scan %s (%s)\n", version, buildTime)
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, err := config.Open(*configPath)
	if err != nil {
		logger.Error("load config failed", "error", err)
		os.Exit(1)
	}
	cfg := store.Get()
	if strings.Contains(cfg.CallbackBaseURL, "127.0.0.1") || strings.Contains(strings.ToLower(cfg.CallbackBaseURL), "localhost") {
		logger.Warn("HTTP 回连基础地址是环回地址，远程目标无法访问；请在持久配置中改为扫描器可达 IP", "callback_base_url", cfg.CallbackBaseURL)
	}
	if strings.Contains(cfg.CallbackLDAPBaseURL, "127.0.0.1") || strings.Contains(strings.ToLower(cfg.CallbackLDAPBaseURL), "localhost") {
		logger.Warn("LDAP 回连基础地址是环回地址，远程目标无法访问；请改为扫描器可达 IP", "callback_ldap_base_url", cfg.CallbackLDAPBaseURL)
	}
	listen := cfg.Listen
	if *listenOverride != "" {
		listen = *listenOverride
	}
	callbacks := callback.NewWithLimit(cfg.CallbackMaxConnections)
	defer callbacks.Close()
	manager := engine.NewManager(store, callbacks)
	apiServer, err := api.New(store, manager, logger)
	if err != nil {
		logger.Error("initialize api failed", "error", err)
		os.Exit(1)
	}
	defer apiServer.Close()
	server := &http.Server{
		Addr: listen, Handler: apiServer.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 130 * time.Second, IdleTimeout: 120 * time.Second,
	}
	callbackListener, err := net.Listen("tcp", cfg.CallbackListen)
	if err != nil {
		logger.Error("callback server listen failed", "listen", cfg.CallbackListen, "error", err)
		os.Exit(1)
	}
	callbackServer := &http.Server{
		Addr: cfg.CallbackListen, Handler: apiServer.CallbackHandler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
	}
	ldapCallbackListener, err := net.Listen("tcp", cfg.CallbackLDAPListen)
	if err != nil {
		logger.Error("LDAP callback sink listen failed", "listen", cfg.CallbackLDAPListen, "error", err)
		os.Exit(1)
	}
	go func() {
		logger.Info("jungle_happy_Scan LDAP callback sink started", "listen", cfg.CallbackLDAPListen, "base_url", cfg.CallbackLDAPBaseURL)
		if serveErr := callbacks.ServeRaw(ldapCallbackListener); serveErr != nil {
			logger.Debug("LDAP callback sink stopped", "error", serveErr)
		}
	}()
	go func() {
		logger.Info("jungle_happy_Scan callback server started", "listen", cfg.CallbackListen, "base_url", cfg.CallbackBaseURL)
		if serveErr := callbackServer.Serve(callbackListener); serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Error("callback server failed", "error", serveErr)
		}
	}()
	go func() {
		logger.Info("jungle_happy_Scan started", "listen", listen, "version", version, "config", store.Path())
		if serveErr := server.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Error("http server failed", "error", serveErr)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	_ = callbackServer.Shutdown(ctx)
	_ = ldapCallbackListener.Close()
	logger.Info("jungle_happy_Scan stopped")
}
