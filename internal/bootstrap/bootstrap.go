package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reviaro/guardfil/internal/approval"
	"github.com/reviaro/guardfil/internal/config"
	"github.com/reviaro/guardfil/internal/content"
	"github.com/reviaro/guardfil/internal/gateway"
	"github.com/reviaro/guardfil/internal/server"
	"github.com/reviaro/guardfil/internal/telemetry"
	"github.com/reviaro/guardfil/internal/webui"
)

func Run(ctx context.Context, path string, log *slog.Logger) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	// The approval service is admitted before any listener opens: a policy that
	// does not compile or an unusable decision log stops startup.
	var svc *approval.Service
	var store *approval.PolicyStore
	var ui *webui.Server
	var decisionLog *os.File
	var contentStore *content.ContentStore
	if c.Approval.Enabled() {
		policyBytes, err := os.ReadFile(c.Approval.PolicyFile)
		if err != nil {
			return err
		}
		// The policy in force is the latest version saved from the UI, unless
		// policy_file was edited since; then the file wins.
		store, policyBytes, err = approval.OpenPolicyStore(c.StateDir, policyBytes)
		if err != nil {
			return err
		}
		if decisionLog, err = approval.OpenDecisionLog(c.Approval.DecisionLog); err != nil {
			return err
		}
		defer decisionLog.Close()
		if svc, err = approval.NewService(policyBytes, decisionLog); err != nil {
			return err
		}
		if err := svc.ConfigureWorkspacePrivacyStore(c.StateDir); err != nil {
			return err
		}
		var contentBytes []byte
		if c.Approval.ContentRulesFile != "" {
			var err error
			contentBytes, err = os.ReadFile(c.Approval.ContentRulesFile)
			if err != nil {
				return err
			}
		}
		// Like the policy: the latest version saved from the UI is in force,
		// unless content_rules_file changed since.
		contentStore, contentBytes, err = content.OpenContentStore(c.StateDir, contentBytes)
		if err != nil {
			return err
		}
		if len(contentBytes) > 0 {
			cr, err := content.ParseRules(contentBytes)
			if err != nil {
				return err
			}
			svc.SetContentRules(cr)
			log.Info("content rules loaded", "lists", len(cr.Lists), "digest", cr.Digest())
		}
		var cat *approval.Catalog
		if c.Approval.ToolCatalog != "" {
			raw, err := os.ReadFile(c.Approval.ToolCatalog)
			if err != nil {
				return err
			}
			if cat, err = approval.ParseCatalog(raw); err != nil {
				return err
			}
		}
		if err = svc.SetCatalog(cat); err != nil {
			return err
		}
		if cat != nil {
			log.Info("tool catalog loaded", "tools", len(cat.Tools()), "digest", cat.Digest())
		}
		if c.Approval.ApproverSocket != "" || c.UI.Serving() {
			if err = svc.EnableAsk(c.Approval.AskTimeout()); err != nil {
				return err
			}
		}
		if c.UI.Serving() {
			token, err := os.ReadFile(c.UI.TokenFile)
			if err != nil {
				return err
			}
			if ui, err = webui.New(svc, store, c.Approval.DecisionLog, token, contentStore); err != nil {
				return err
			}
		}
	}
	var gw *gateway.Gateway
	if c.Gateway.Enabled() {
		if gw, err = gateway.New(c.Gateway, svc, log); err != nil {
			return err
		}
	}
	if svc != nil {
		svc.SetApprovalSocket(c.Approval.Socket)
		if gw != nil {
			svc.SetGatewayRegistrar(gw)
		}
	}
	ready := false
	s, err := server.New(c, &ready, &telemetry.Counters{})
	if err != nil {
		return err
	}
	if err = s.Start(c); err != nil {
		sd, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return errors.Join(err, s.Shutdown(sd))
	}
	var approvalListener net.Listener
	var approver *http.Server
	approvalDone := make(chan error, 1)
	approverDone := make(chan error, 1)
	if svc != nil {
		if approvalListener, err = approval.ListenUnix(c.Approval.Socket); err != nil {
			sd, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			return errors.Join(err, s.Shutdown(sd))
		}
		go func() { approvalDone <- svc.Serve(approvalListener) }()
		if c.Approval.ApproverSocket != "" {
			al, err := approval.ListenUnix(c.Approval.ApproverSocket)
			if err != nil {
				return errors.Join(err, shutdownAll(s, svc, approvalListener, approvalDone, nil, nil, nil, nil))
			}
			approver = &http.Server{Handler: svc.ApproverHandler(), ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, MaxHeaderBytes: 8 << 10}
			go func() {
				if err := approver.Serve(al); !errors.Is(err, http.ErrServerClosed) {
					approverDone <- err
					return
				}
				approverDone <- nil
			}()
		}
		if c.Approval.FilterSocket != "" {
			fl, err := approval.ListenUnix(c.Approval.FilterSocket)
			if err != nil {
				return errors.Join(err, shutdownAll(s, svc, approvalListener, approvalDone, approver, approverDone, nil, nil))
			}
			go func() { _ = svc.ServeFilter(fl) }()
			defer func() { _ = fl.Close(); _ = os.Remove(c.Approval.FilterSocket) }()
		}
		log.Info("approval service started", "policy_digest", svc.PolicyDigest(), "policy_version", store.Current(),
			"ask_me", svc.AskEnabled())
	}
	var uiServer *http.Server
	uiDone := make(chan error, 1)
	if ui != nil {
		ul, err := net.Listen("tcp", c.UI.Address)
		if err != nil {
			return errors.Join(err, shutdownAll(s, svc, approvalListener, approvalDone, approver, approverDone, nil, nil))
		}
		rh, rt, idle, _ := config.ServerTimeouts()
		uiServer = &http.Server{Handler: ui.Handler(), ReadHeaderTimeout: rh, ReadTimeout: rt, WriteTimeout: rt,
			IdleTimeout: idle, MaxHeaderBytes: config.MaxHeaderBytes}
		go func() {
			if err := uiServer.Serve(ul); !errors.Is(err, http.ErrServerClosed) {
				uiDone <- err
				return
			}
			uiDone <- nil
		}()
		log.Info("ui started", "address", c.UI.Address)
	} else if c.UI.Installed() {
		log.Info("ui installed but inactive; no listener")
	}
	var gwServer *http.Server
	gwDone := make(chan error, 1)
	gwListeners := 0
	if gw != nil {
		var gls []net.Listener
		closeGls := func() {
			for _, l := range gls {
				_ = l.Close()
			}
		}
		if c.Gateway.Address != "" {
			gl, err := net.Listen("tcp", c.Gateway.Address)
			if err != nil {
				return errors.Join(err, shutdownAll(s, svc, approvalListener, approvalDone, approver, approverDone, uiServer, uiDone))
			}
			gls = append(gls, gl)
		}
		if c.Gateway.Socket != "" {
			gl, err := approval.ListenUnix(c.Gateway.Socket)
			if err != nil {
				closeGls()
				return errors.Join(fmt.Errorf("gateway socket: %w", err), shutdownAll(s, svc, approvalListener, approvalDone, approver, approverDone, uiServer, uiDone))
			}
			gls = append(gls, gl)
		}
		// A held ("ask me") request waits for the owner, so writes may take up to the ask timeout.
		rh, rt, idle, _ := config.ServerTimeouts()
		gwServer = &http.Server{Handler: gw, ReadHeaderTimeout: rh, ReadTimeout: rt,
			WriteTimeout: c.Approval.AskTimeout() + 45*time.Second, IdleTimeout: idle, MaxHeaderBytes: config.MaxHeaderBytes}
		gwDone = make(chan error, len(gls))
		for _, gl := range gls {
			go func(gl net.Listener) {
				if err := gwServer.Serve(gl); !errors.Is(err, http.ErrServerClosed) {
					gwDone <- err
					return
				}
				gwDone <- nil
			}(gl)
		}
		gwListeners = len(gls)
		log.Info("api gateway started", "address", c.Gateway.Address, "socket", c.Gateway.Socket, "upstreams", len(c.Gateway.Upstreams))
	}
	ready = true
	log.Info("guardfil started")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ctx.Done():
	case <-stop:
	}
	ready = false
	var out error
	if gwServer != nil {
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		svc.Close() // held gateway requests end now, as BLOCK
		out = errors.Join(out, gwServer.Shutdown(sd))
		for i := 0; i < gwListeners; i++ {
			out = errors.Join(out, <-gwDone)
		}
		cancel()
		if c.Gateway.Socket != "" {
			_ = os.Remove(c.Gateway.Socket)
		}
	}
	if uiServer != nil {
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out = errors.Join(out, uiServer.Shutdown(sd), <-uiDone)
		cancel()
	}
	if approver != nil {
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out = errors.Join(out, approver.Shutdown(sd), <-approverDone)
		cancel()
		_ = os.Remove(c.Approval.ApproverSocket)
	}
	if approvalListener != nil {
		svc.Close() // held "ask me" calls end now, as BLOCK
		_ = approvalListener.Close()
		out = errors.Join(out, <-approvalDone)
		_ = os.Remove(c.Approval.Socket)
	}
	sd, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return errors.Join(out, s.Shutdown(sd))
}

// shutdownAll stops what Run started before a later listener failed.
func shutdownAll(s *server.Servers, svc *approval.Service, al net.Listener, alDone chan error, approver *http.Server, approverDone chan error, ui *http.Server, uiDone chan error) error {
	var out error
	if ui != nil {
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out = errors.Join(out, ui.Shutdown(sd), <-uiDone)
		cancel()
	}
	if approver != nil {
		sd, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out = errors.Join(out, approver.Shutdown(sd), <-approverDone)
		cancel()
	}
	if al != nil {
		if svc != nil {
			svc.Close()
		}
		_ = al.Close()
		out = errors.Join(out, <-alDone)
	}
	sd, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return errors.Join(out, s.Shutdown(sd))
}

// ValidateConfig loads and verifies the non-secret configuration file, along with
// compiling any referenced policy, validating the tool catalog, and checking
// that any enabled gateway routes match tools in the catalog.
func ValidateConfig(path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	var cat *approval.Catalog
	if c.Approval.Enabled() {
		policyBytes, err := os.ReadFile(c.Approval.PolicyFile)
		if err != nil {
			return fmt.Errorf("policy file: %w", err)
		}
		_, policyBytes, err = approval.OpenPolicyStore(c.StateDir, policyBytes)
		if err != nil {
			return err
		}
		svc, err := approval.NewService(policyBytes, io.Discard)
		if err != nil {
			return fmt.Errorf("policy compile: %w", err)
		}
		defer svc.Close()
		var cb []byte
		if c.Approval.ContentRulesFile != "" {
			cb, err = os.ReadFile(c.Approval.ContentRulesFile)
			if err != nil {
				return fmt.Errorf("content rules file: %w", err)
			}
		}
		_, cb, err = content.OpenContentStore(c.StateDir, cb)
		if err != nil {
			return err
		}
		if len(cb) > 0 {
			if _, err := content.ParseRules(cb); err != nil {
				return fmt.Errorf("content rules: %w", err)
			}
		}
		if c.Approval.ToolCatalog != "" {
			raw, err := os.ReadFile(c.Approval.ToolCatalog)
			if err != nil {
				return fmt.Errorf("tool catalog file: %w", err)
			}
			cat, err = approval.ParseCatalog(raw)
			if err != nil {
				return fmt.Errorf("tool catalog: %w", err)
			}
		}
		if err := svc.SetCatalog(cat); err != nil {
			return err
		}
	}
	if c.Gateway.Enabled() && cat != nil {
		for _, u := range c.Gateway.Upstreams {
			for _, r := range u.Routes {
				if !cat.Has(r.Tool) {
					return fmt.Errorf("gateway %s route %s %s: tool %s is not in the tool catalog", u.Name, r.Method, r.Path, r.Tool)
				}
			}
		}
	}
	return nil
}

// ValidateCatalog parses and validates a tool catalog document (or multi-document stream).
func ValidateCatalog(raw []byte) (*approval.Catalog, error) {
	return approval.ParseCatalog(raw)
}
