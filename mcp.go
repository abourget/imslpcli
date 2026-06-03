package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"github.com/ryanuber/columnize"
)

// --- In-memory OAuth state (ephemeral, per-process) ---
// Client registrations are persisted to disk (see clientRegistry) so that
// restarts don't invalidate clients that have already completed DCR.

var (
	authCodes = map[string]authCodeEntry{}
)

type authCodeEntry struct {
	CodeChallenge string
	LoginToken    string
	UserID        int
	Username      string
	ClientID      string
	RedirectURI   string
	Scope         string
	ExpiresAt     time.Time
}

type registeredClient struct {
	Secret       string
	RedirectURIs []string
}

// clientRegistry is a simple on-disk "database" for dynamically registered
// OAuth clients (from DCR at POST /register). It survives server restarts
// so that in-progress authorization flows don't have to re-register.
type clientRegistry struct {
	mu       sync.RWMutex
	clients  map[string]registeredClient
	filePath string
}

func newClientRegistry(filePath string) *clientRegistry {
	if filePath == "" {
		filePath = "mcp-clients.json"
	}
	reg := &clientRegistry{
		clients:  make(map[string]registeredClient),
		filePath: filePath,
	}
	reg.load()
	return reg
}

func (r *clientRegistry) load() {
	data, err := os.ReadFile(r.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("warning: failed to read clients file %s: %v", r.filePath, err)
		}
		return
	}
	var m map[string]registeredClient
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("warning: failed to parse clients file %s: %v", r.filePath, err)
		return
	}
	r.mu.Lock()
	r.clients = m
	r.mu.Unlock()
	log.Printf("loaded %d persisted OAuth clients from %s", len(m), r.filePath)
}

func (r *clientRegistry) save() {
	r.mu.RLock()
	data, _ := json.MarshalIndent(r.clients, "", "  ")
	r.mu.RUnlock()

	tmp := r.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("warning: failed to write temp clients file %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, r.filePath); err != nil {
		log.Printf("warning: failed to atomically update clients file %s: %v", r.filePath, err)
		return
	}
}

func (r *clientRegistry) register(clientID string, c registeredClient) {
	r.mu.Lock()
	r.clients[clientID] = c
	r.mu.Unlock()
	r.save()
}

func (r *clientRegistry) get(clientID string) (registeredClient, bool) {
	r.mu.RLock()
	c, ok := r.clients[clientID]
	r.mu.RUnlock()
	return c, ok
}

type persistedSession struct {
	UserID string `json:"userID"`
}

type sessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string]persistedSession
	filePath string
}

func newSessionRegistry(filePath string) *sessionRegistry {
	if filePath == "" {
		filePath = "mcp-sessions.json"
	}
	reg := &sessionRegistry{
		sessions: make(map[string]persistedSession),
		filePath: filePath,
	}
	reg.load()
	return reg
}

func (r *sessionRegistry) load() {
	data, err := os.ReadFile(r.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("warning: failed to read sessions file %s: %v", r.filePath, err)
		}
		return
	}
	var m map[string]persistedSession
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("warning: failed to parse sessions file %s: %v", r.filePath, err)
		return
	}
	r.mu.Lock()
	r.sessions = m
	r.mu.Unlock()
	log.Printf("loaded %d persisted MCP sessions from %s", len(m), r.filePath)
}

func (r *sessionRegistry) save() {
	r.mu.RLock()
	data, _ := json.MarshalIndent(r.sessions, "", "  ")
	r.mu.RUnlock()

	tmp := r.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("warning: failed to write temp sessions file %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, r.filePath); err != nil {
		log.Printf("warning: failed to atomically update sessions file %s: %v", r.filePath, err)
		return
	}
}

func (r *sessionRegistry) put(sessionID string, sess persistedSession) {
	r.mu.Lock()
	r.sessions[sessionID] = sess
	r.mu.Unlock()
	r.save()
}

func (r *sessionRegistry) get(sessionID string) (persistedSession, bool) {
	r.mu.RLock()
	s, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	return s, ok
}

func (r *sessionRegistry) remove(sessionID string) {
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()
	r.save()
}

// statusWriter captures the HTTP status code for access logging.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
}

// loggingMiddleware provides basic access logging for all HTTP hits to the server
// (method, path, status, duration, remote addr, and username when the request was
// authenticated via our OAuth JWT flow).
func (s *imslpMCPServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		dur := time.Since(start)

		user := ""
		if ti := auth.TokenInfoFromContext(r.Context()); ti != nil {
			if uname, ok := ti.Extra["imslp_username"].(string); ok && uname != "" {
				user = " user=" + uname
			} else if ti.UserID != "" {
				user = " user=" + ti.UserID
			}
		}

		q := r.URL.RawQuery
		if q != "" {
			q = "?" + q
		}
		ua := r.Header.Get("User-Agent")
		if ua == "" {
			ua = "-"
		}
		// Show real client IP when behind ngrok, cloudflare, etc.
		realIP := r.Header.Get("X-Forwarded-For")
		if realIP == "" {
			realIP = r.Header.Get("X-Real-IP")
		}
		if realIP == "" {
			realIP = r.RemoteAddr
		}
		log.Printf("HTTP %s %s %s%s -> %d (%s)%s ua=%q", realIP, r.Method, r.URL.Path, q, sw.status, dur, user, ua)
	})
}

// createRequestLoggingMiddleware logs MCP protocol-level method calls (initialize, tools/list, tools/call etc.)
// This complements the HTTP access log (which already includes the authenticated user for /mcp requests).
func (s *imslpMCPServer) createRequestLoggingMiddleware() mcp.Middleware {
	return func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			start := time.Now()
			sid := ""
			if sess := req.GetSession(); sess != nil {
				sid = sess.ID()
				if len(sid) > 8 {
					sid = sid[:8]
				}
			}
			user := ""
			if ti := auth.TokenInfoFromContext(ctx); ti != nil {
				if uname, ok := ti.Extra["imslp_username"].(string); ok && uname != "" {
					user = uname
				} else if ti.UserID != "" {
					user = ti.UserID
				}
			}
			if user == "" {
				if ctr, ok := req.(*mcp.CallToolRequest); ok && ctr.Extra != nil && ctr.Extra.TokenInfo != nil {
					ti := ctr.Extra.TokenInfo
					if uname, ok := ti.Extra["imslp_username"].(string); ok && uname != "" {
						user = uname
					} else if ti.UserID != "" {
						user = ti.UserID
					}
				}
			}
			if user != "" {
				log.Printf("MCP session=%s method=%s user=%s", sid, method, user)
			} else {
				log.Printf("MCP session=%s method=%s", sid, method)
			}
			res, err := next(ctx, method, req)
			if user != "" {
				log.Printf("MCP session=%s method=%s user=%s done (%s) err=%v", sid, method, user, time.Since(start), err)
			} else {
				log.Printf("MCP session=%s method=%s done (%s) err=%v", sid, method, time.Since(start), err)
			}
			return res, err
		}
	}
}

// --- Server ---

type imslpMCPServer struct {
	baseURL   string
	jwtSecret []byte
	mcpSrv    *mcp.Server
	clients   *clientRegistry
	sessions  *sessionRegistry
}

func newIMSLPMCPServer(baseURL string, jwtSecret []byte, clientsFile, sessionsFile string) *imslpMCPServer {
	s := &imslpMCPServer{
		baseURL:   strings.TrimRight(baseURL, "/"),
		jwtSecret: jwtSecret,
		clients:   newClientRegistry(clientsFile),
		sessions:  newSessionRegistry(sessionsFile),
	}
	s.mcpSrv = s.createMCPServer()
	return s
}

func (s *imslpMCPServer) issuer() string { return s.baseURL }

// registerHandlers wires the OAuth AS endpoints + protected MCP RS.
// It returns the final top-level handler (with access logging middleware applied).
func (s *imslpMCPServer) registerHandlers(mux *http.ServeMux) http.Handler {
	// AS metadata (with CORS for client discovery)
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthServerMetadata)

	// Protected resource metadata (SDK helper adds CORS)
	pr := &oauthex.ProtectedResourceMetadata{
		Resource:             s.baseURL + "/mcp",
		AuthorizationServers: []string{s.issuer()},
		ScopesSupported:      []string{"mcp"},
	}
	mux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadataHandler(pr))

	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)

	// MCP Resource Server (streamable HTTP)
	// DisableLocalhostProtection is enabled because this server is designed
	// to be hosted publicly (via --base-url or APP_BASE_URL), often behind
	// tunnels/proxies with public Host headers (e.g. imslp-mcp.exe.xyz).
	// The protection is for local-only dev servers to mitigate DNS rebinding.
	stream := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return s.mcpSrv
	}, &mcp.StreamableHTTPOptions{
		DisableLocalhostProtection: true,
	})
	authMW := auth.RequireBearerToken(s.verifyBearer, &auth.RequireBearerTokenOptions{
		Scopes:              []string{"mcp"},
		ResourceMetadataURL: s.baseURL + "/.well-known/oauth-protected-resource",
	})
	debuggedStream := s.mcpDebugWrapper(stream)
	mcpHandler := authMW(debuggedStream)

	mux.Handle("/mcp", mcpHandler)

	// Support clients configured with just the base public URL (https://imslp-mcp.exe.xyz)
	// by also accepting the MCP protocol at root. Browser GETs still get the info page.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if isMCPProtocolRequest(r) {
			mcpHandler.ServeHTTP(w, r)
			return
		}
		s.handleRoot(w, r)
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "imslp-mcp"})
	})

	// Helpful 404s for common alternative transport paths some clients may try
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "This server implements Streamable HTTP (configure the full /mcp URL or use the base which also works for MCP traffic). SSE transport is not supported.", http.StatusNotFound)
	})

	return s.loggingMiddleware(mux)
}

// isMCPProtocolRequest detects requests that should be handled by the Streamable HTTP MCP handler
// rather than the human-friendly root page. This lets users "punch in" the bare public base URL
// in some clients while still serving a nice info page to browsers.
func isMCPProtocolRequest(r *http.Request) bool {
	// Browsers asking for HTML should get the info page
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		return false
	}
	// Standard MCP over Streamable HTTP: POST with JSON body, or GET/SSE for the stream
	if r.Method == http.MethodPost && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/event-stream") || strings.Contains(accept, "application/json") {
		return true
	}
	if r.Header.Get("Mcp-Protocol-Version") != "" || r.Header.Get("MCP-Protocol-Version") != "" {
		return true
	}
	return false
}

// setCORS sets permissive CORS headers suitable for the OAuth/DCR endpoints
// so that browser-based MCP inspectors and web clients can call them cross-origin.
func setCORS(w http.ResponseWriter, allowedMethods string) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "86400")
}

// mcpDebugWrapper logs details for every request that reaches the MCP stream handler
// (i.e. after the bearer auth middleware has accepted the token). This helps debug
// 401 vs 403 cases and session user mismatches.
func (s *imslpMCPServer) mcpDebugWrapper(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fullSessID := r.Header.Get("Mcp-Session-Id")
		logSessID := fullSessID
		if len(logSessID) > 12 {
			logSessID = logSessID[:12] + "..."
		}
		ti := auth.TokenInfoFromContext(r.Context())
		tokenUser := ""
		if ti != nil {
			tokenUser = ti.UserID
			if tokenUser == "" {
				if u, ok := ti.Extra["imslp_username"].(string); ok && u != "" {
					tokenUser = u
				}
			}
		}
		log.Printf("MCP post-auth: path=%s session=%s token_user=%s", r.URL.Path, logSessID, tokenUser)

		// Check persisted session binding (loaded on boot from --sessions-file) so that
		// a server reboot does not let other users hijack stale Mcp-Session-Ids (the
		// binding is the persisted equivalent of the SDK's in-memory userID guard).
		// Only the recorded owner may use/refresh the sessionID. We (re)write on every
		// use so the on-disk copy is current.
		if fullSessID != "" && tokenUser != "" {
			if ps, ok := s.sessions.get(fullSessID); ok && ps.UserID != tokenUser {
				log.Printf("MCP returning 403 (persisted session user mismatch for session=%s persisted_user=%s token_user=%s)", logSessID, ps.UserID, tokenUser)
				http.Error(w, "session user mismatch", http.StatusForbidden)
				return
			}
			s.sessions.put(fullSessID, persistedSession{UserID: tokenUser})
		}

		// Wrap to detect 403s returned from inside the stream handler (e.g. session user mismatch)
		sw := &statusWriter{ResponseWriter: w, status: 200}
		inner.ServeHTTP(sw, r)
		if sw.status == 403 {
			log.Printf("MCP returning 403 (likely session user mismatch for session=%s token_user=%s)", logSessID, tokenUser)
		}

		// On explicit session close (DELETE), drop from our persisted registry too so the
		// on-disk sessions don't accumulate closed ones forever.
		if r.Method == http.MethodDelete && sw.status == http.StatusNoContent {
			sid := fullSessID
			if sid != "" {
				s.sessions.remove(sid)
				log.Printf("MCP removed closed session=%s (persisted cleaned)", sid)
			}
		}

		// Also persist when the server *assigns* a new session ID in the response (happens on
		// initialize for brand new sessions). This ensures the binding is on disk immediately
		// after the client is told its Mcp-Session-Id, even before any follow-up request.
		if assigned := w.Header().Get("Mcp-Session-Id"); assigned != "" && tokenUser != "" {
			wasNew := false
			if _, ok := s.sessions.get(assigned); !ok {
				wasNew = true
			}
			if ps, ok := s.sessions.get(assigned); ok && ps.UserID != tokenUser {
				log.Printf("MCP assigned session=%s but persisted owner mismatch (user=%s vs %s)", assigned, ps.UserID, tokenUser)
			} else {
				s.sessions.put(assigned, persistedSession{UserID: tokenUser})
				if wasNew {
					log.Printf("MCP persisted newly assigned session=%s for user=%s", assigned, tokenUser)
				}
			}
		}
	})
}

func (s *imslpMCPServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>IMSLP MCP</title>
<style>body{font-family:system-ui;background:#111;color:#ddd;padding:2rem} a{color:#6cf} code{background:#222;padding:2px 4px;border-radius:3px}</style>
<h1>IMSLP MCP Server</h1>
<p>Combined OAuth2 Authorization Server + MCP Resource Server (streamable HTTP).</p>
<p><strong>Configure your MCP client (Claude Desktop, Grok, etc.) with this URL:</strong><br>
<code>%[1]s/mcp</code></p>
<p>Some clients also accept just the base URL (<code>%[1]s</code>); we support the MCP protocol at both <code>/mcp</code> and root for convenience.</p>
<ul>
<li>MCP endpoint (recommended): <a href="%[1]s/mcp">%[1]s/mcp</a> (requires Bearer JWT)</li>
<li>AS metadata: <a href="%[1]s/.well-known/oauth-authorization-server">%[1]s/.well-known/oauth-authorization-server</a></li>
<li>PR metadata: <a href="%[1]s/.well-known/oauth-protected-resource">%[1]s/.well-known/oauth-protected-resource</a></li>
<li>Dynamic client registration: POST %[1]s/register</li>
<li>Login (start OAuth): %[1]s/authorize (clients redirect users here)</li>
</ul>
<p>Use with Claude Desktop / other MCP clients by pointing them at the full <code>/mcp</code> URL (or the base). Authentication is handled via standard OAuth2 (DCR + PKCE + the login form does real <code>user.login</code> against IMSLP).</p>
`, s.baseURL)
}

// --- OAuth AS: metadata, DCR, authorize (form), token ---

func (s *imslpMCPServer) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	meta := &oauthex.AuthServerMeta{
		Issuer:                            s.issuer(),
		AuthorizationEndpoint:             s.baseURL + "/authorize",
		TokenEndpoint:                     s.baseURL + "/token",
		RegistrationEndpoint:              s.baseURL + "/register",
		ScopesSupported:                   []string{"mcp"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

func (s *imslpMCPServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	setCORS(w, "POST, OPTIONS")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var meta oauthex.ClientRegistrationMetadata
	if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
		writeRegError(w, "invalid_request", "bad JSON body")
		return
	}
	if len(meta.RedirectURIs) == 0 {
		writeRegError(w, "invalid_redirect_uri", "redirect_uris is required and must be non-empty")
		return
	}
	authMethod := meta.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	var secret string
	if authMethod == "none" {
		secret = ""
	} else {
		secret = generateID()
	}
	clientID := generateID()
	s.clients.register(clientID, registeredClient{
		Secret:       secret,
		RedirectURIs: append([]string(nil), meta.RedirectURIs...),
	})
	respMeta := meta
	respMeta.TokenEndpointAuthMethod = authMethod
	if len(respMeta.GrantTypes) == 0 {
		respMeta.GrantTypes = []string{"authorization_code"}
	}
	if len(respMeta.ResponseTypes) == 0 {
		respMeta.ResponseTypes = []string{"code"}
	}
	resp := &oauthex.ClientRegistrationResponse{
		ClientRegistrationMetadata: respMeta,
		ClientID:                   clientID,
		ClientIDIssuedAt:           time.Now(),
	}
	if secret != "" {
		resp.ClientSecret = secret
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)

	log.Printf("AUTH DCR registered client_id=%s name=%q redirects=%v from %s", clientID, meta.ClientName, meta.RedirectURIs, r.RemoteAddr)
}

func writeRegError(w http.ResponseWriter, code, desc string) {
	setCORS(w, "POST, OPTIONS")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(&oauthex.ClientRegistrationError{
		ErrorCode:        code,
		ErrorDescription: desc,
	})
}

func (s *imslpMCPServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	setCORS(w, "GET, POST, OPTIONS")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method == http.MethodGet {
		s.showLoginForm(w, r)
		return
	}
	if r.Method == http.MethodPost {
		s.handleLoginSubmit(w, r)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

type loginFormData struct {
	Error               string
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Resource            string
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IMSLP • Authorize MCP Access</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; background:#0f0f0f; color:#e5e5e5; margin:0; padding:2rem; display:flex; align-items:center; justify-content:center; min-height:100vh; }
.card { background:#171717; border:1px solid #2a2a2a; border-radius:12px; padding:2rem; width:100%; max-width:420px; box-shadow:0 10px 30px rgba(0,0,0,.4); }
h1 { margin:0 0 .25rem; font-size:1.35rem; }
p.sub { margin:0 0 1.25rem; color:#888; font-size:.95rem; }
label { display:block; font-size:.8rem; color:#999; margin:.6rem 0 .2rem; }
input[type="text"], input[type="password"] { width:100%; box-sizing:border-box; padding:.55rem .65rem; border:1px solid #333; border-radius:6px; background:#111; color:#eee; font-size:1rem; }
input:focus { outline:none; border-color:#0a7; }
.btn { margin-top:1rem; width:100%; padding:.65rem; background:#0a7; color:#fff; border:none; border-radius:6px; font-size:1rem; cursor:pointer; }
.btn:hover { background:#0b8; }
.error { background:#3a1515; color:#f88; padding:.6rem .75rem; border-radius:6px; margin-bottom:.9rem; font-size:.9rem; }
.note { font-size:.75rem; color:#666; margin-top:1rem; line-height:1.3; }
</style></head>
<body>
<div class="card">
<h1>Sign in with IMSLP</h1>
<p class="sub">Authorize this MCP client to read/write your scores and setlists.</p>
{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
<form method="POST" action="/authorize" autocomplete="on">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<input type="hidden" name="resource" value="{{.Resource}}">
<label for="u">IMSLP username or email</label>
<input id="u" name="username" type="text" required autofocus>
<label for="p">Password</label>
<input id="p" name="password" type="password" required>
<button class="btn" type="submit">Log in to IMSLP and Authorize</button>
</form>
<div class="note">Your password is sent only to this server, which performs the real IMSLP login (like <code>imslpcli login</code>). We never store the password — only the resulting login token (inside a short-lived code, then a signed JWT returned to the client).</div>
</div>
</body></html>`))

func (s *imslpMCPServer) showLoginForm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data := loginFormData{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Scope:               q.Get("scope"),
		Resource:            q.Get("resource"),
	}
	s.renderLogin(w, data)
}

func (s *imslpMCPServer) renderLogin(w http.ResponseWriter, data loginFormData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := loginTmpl.Execute(&buf, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

func (s *imslpMCPServer) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	scope := r.FormValue("scope")

	if username == "" || password == "" {
		s.renderLogin(w, loginFormData{Error: "username and password are required", ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: codeChallenge, Scope: scope})
		return
	}

	reg, ok := s.clients.get(clientID)
	if !ok {
		s.renderLogin(w, loginFormData{Error: "unknown client_id — the client should have performed dynamic registration (POST /register) first", ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: codeChallenge, Scope: scope})
		return
	}
	if redirectURI == "" || !stringSliceContains(reg.RedirectURIs, redirectURI) {
		s.renderLogin(w, loginFormData{Error: "redirect_uri is not registered for this client", ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: codeChallenge, Scope: scope})
		return
	}
	if codeChallenge == "" {
		s.renderLogin(w, loginFormData{Error: "PKCE code_challenge is required", ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: codeChallenge, Scope: scope})
		return
	}

	// Real IMSLP authentication (exactly like `imslpcli login`)
	cli := NewClientWithToken("")
	if err := cli.Login(username, password); err != nil {
		s.renderLogin(w, loginFormData{Error: "IMSLP login failed: " + err.Error(), ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: codeChallenge, Scope: scope})
		return
	}

	// Issue one-time authorization code bound to the loginToken + PKCE challenge
	code := generateID()
	authCodes[code] = authCodeEntry{
		CodeChallenge: codeChallenge,
		LoginToken:    cli.LoginToken,
		UserID:        cli.UserID,
		Username:      cli.Username,
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	log.Printf("AUTH form login successful user=%s (id=%d) client=%s redirect=%s from %s", cli.Username, cli.UserID, clientID, redirectURI, r.RemoteAddr)

	// Redirect back to the client's registered redirect_uri (desktop callback etc.)
	iss := url.QueryEscape(s.issuer())
	to := redirectURI
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	to += sep + "code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state) + "&iss=" + iss
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *imslpMCPServer) handleToken(w http.ResponseWriter, r *http.Request) {
	setCORS(w, "POST, OPTIONS")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.handleAuthorizationCodeExchange(w, r)
	default:
		writeTokenError(w, "unsupported_grant_type", "only authorization_code is supported")
	}
}

func (s *imslpMCPServer) handleAuthorizationCodeExchange(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		writeTokenError(w, "invalid_request", "code is required")
		return
	}

	clientID := r.FormValue("client_id")
	reg, err := s.authenticateClientForToken(r, clientID)
	if err != nil {
		writeTokenError(w, "invalid_client", err.Error())
		return
	}

	entry, ok := authCodes[code]
	if !ok {
		writeTokenError(w, "invalid_grant", "code not found or already used")
		return
	}
	delete(authCodes, code)

	if time.Now().After(entry.ExpiresAt) {
		writeTokenError(w, "invalid_grant", "code expired")
		return
	}
	if entry.ClientID != "" && entry.ClientID != clientID {
		writeTokenError(w, "invalid_grant", "client mismatch for code")
		return
	}
	if !stringSliceContains(reg.RedirectURIs, entry.RedirectURI) {
		// should not happen
		writeTokenError(w, "invalid_grant", "redirect_uri not valid for client")
		return
	}

	verifier := r.FormValue("code_verifier")
	if verifier == "" {
		writeTokenError(w, "invalid_request", "code_verifier is required (PKCE)")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	if expected != entry.CodeChallenge {
		writeTokenError(w, "invalid_grant", "PKCE verification failed")
		return
	}

	// Optional redirect_uri check in token request (RFC)
	if ru := r.FormValue("redirect_uri"); ru != "" && ru != entry.RedirectURI {
		writeTokenError(w, "invalid_grant", "redirect_uri mismatch in token request")
		return
	}

	// Mint JWT containing the user's IMSLP loginToken (this is what the MCP tools will extract and use)
	jwtStr, exp, err := s.issueJWT(entry.LoginToken, entry.UserID, entry.Username)
	if err != nil {
		writeTokenError(w, "server_error", "failed to sign token")
		return
	}

	resp := map[string]any{
		"access_token": jwtStr,
		"token_type":   "Bearer",
		"expires_in":   int64(time.Until(exp).Seconds()),
	}
	if entry.Scope != "" {
		resp["scope"] = entry.Scope
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)

	log.Printf("AUTH token exchange success user=%s (id=%d) client=%s from %s (issued JWT)", entry.Username, entry.UserID, clientID, r.RemoteAddr)
}

func (s *imslpMCPServer) authenticateClientForToken(r *http.Request, fallbackClientID string) (registeredClient, error) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	if clientID == "" {
		clientID = fallbackClientID
	}
	reg, ok := s.clients.get(clientID)
	if !ok {
		return registeredClient{}, fmt.Errorf("unknown client_id")
	}
	if reg.Secret != "" {
		if clientSecret != reg.Secret {
			return registeredClient{}, fmt.Errorf("invalid client secret")
		}
	}
	// public clients (secret=="") are allowed with no client_secret (PKCE is the protection)
	return reg, nil
}

func (s *imslpMCPServer) issueJWT(loginToken string, userID int, username string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(30 * 24 * time.Hour) // 30 days — the embedded loginToken is the long-lived credential
	claims := jwt.MapClaims{
		"iss":               s.issuer(),
		"aud":               s.baseURL + "/mcp",
		"sub":               username,
		"iat":               now.Unix(),
		"nbf":               now.Unix(),
		"exp":               exp.Unix(),
		"imslp_login_token": loginToken,
		"imslp_user_id":     userID,
		"imslp_username":    username,
		"scopes":            []string{"mcp"},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := t.SignedString(s.jwtSecret)
	return signed, exp, err
}

func (s *imslpMCPServer) verifyBearer(ctx context.Context, tokenStr string, req *http.Request) (*auth.TokenInfo, error) {
	preview := tokenStr
	if len(preview) > 20 {
		preview = preview[:20] + "..."
	}
	log.Printf("VERIFY bearer: remote=%s path=%s token_preview=%s", req.RemoteAddr, req.URL.Path, preview)

	tok, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("VERIFY FAIL: bad alg %v", t.Header["alg"])
			return nil, fmt.Errorf("unexpected alg %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
	if err != nil {
		log.Printf("VERIFY FAIL: jwt parse: %v", err)
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	if !tok.Valid {
		log.Printf("VERIFY FAIL: token !Valid")
		return nil, auth.ErrInvalidToken
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("VERIFY FAIL: claims not MapClaims")
		return nil, fmt.Errorf("%w: invalid claims", auth.ErrInvalidToken)
	}

	var exp time.Time
	if e, ok := claims["exp"].(float64); ok {
		exp = time.Unix(int64(e), 0)
		if time.Now().After(exp) {
			log.Printf("VERIFY FAIL: token expired (exp=%v)", exp)
			return nil, auth.ErrInvalidToken
		}
	}

	sub, _ := claims["sub"].(string)
	username, _ := claims["imslp_username"].(string)
	loginTok, hasLogin := claims["imslp_login_token"].(string)
	if !hasLogin || loginTok == "" {
		log.Printf("VERIFY FAIL: missing or empty imslp_login_token in claims sub=%s", sub)
		return nil, fmt.Errorf("%w: no imslp_login_token in JWT", auth.ErrInvalidToken)
	}

	log.Printf("VERIFY SUCCESS: sub=%s imslp_username=%s has_login_token=true exp=%v", sub, username, exp)

	ti := &auth.TokenInfo{
		Scopes:     []string{"mcp"},
		Expiration: exp,
		Extra: map[string]any{
			"imslp_login_token": loginTok,
			"imslp_user_id":     claims["imslp_user_id"],
			"imslp_username":    username,
		},
	}
	if sub != "" {
		ti.UserID = sub
	}
	return ti, nil
}

func writeTokenError(w http.ResponseWriter, code, desc string) {
	setCORS(w, "POST, OPTIONS")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

func generateID() string { return rand.Text() }

func stringSliceContains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// boolPtr is a helper to create *bool for ToolAnnotations.DestructiveHint etc.
func boolPtr(b bool) *bool { return &b }

// --- MCP tools (all IMSLP functionality exposed) ---

func (s *imslpMCPServer) createMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "imslp", Version: "0.1.0"}, nil)

	// Protocol-level logging for MCP method calls (in addition to HTTP access logs).
	srv.AddReceivingMiddleware(s.createRequestLoggingMiddleware())

	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_whoami",
		Description: "Show the IMSLP user identity associated with the current MCP session (from the OAuth JWT).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.toolWhoami)

	// setlist management
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_list_setlists",
		Description: "List all current (non-deleted) setlists with their IDs, names and number of scores.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.toolListSetlists)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_search_setlists",
		Description: "Search setlists by (partial) name. Returns ID + Name for each match.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.toolSearchSetlists)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_show_setlist",
		Description: "Show one setlist (by ID or name) including the list of scores with their Work Titles.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.toolShowSetlist)
	mcp.AddTool(srv, &mcp.Tool{Name: "imslp_create_setlist", Description: "Create a brand new setlist. Optionally include initial score IDs."}, s.toolCreateSetlist)
	mcp.AddTool(srv, &mcp.Tool{Name: "imslp_clone_setlist", Description: "Clone an existing setlist (by ID or name) under a new name."}, s.toolCloneSetlist)
	mcp.AddTool(srv, &mcp.Tool{Name: "imslp_rename_setlist", Description: "Rename a setlist (by ID or name)."}, s.toolRenameSetlist)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_delete_setlist",
		Description: "Delete a setlist (by ID or name).",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: boolPtr(true)},
	}, s.toolDeleteSetlist)
	mcp.AddTool(srv, &mcp.Tool{Name: "imslp_append_to_setlist", Description: "Append a score (by its item ID) to the end of a setlist (by ID or name)."}, s.toolAppendToSetlist)
	mcp.AddTool(srv, &mcp.Tool{Name: "imslp_prepend_to_setlist", Description: "Prepend a score to the start of a setlist."}, s.toolPrependToSetlist)
	mcp.AddTool(srv, &mcp.Tool{Name: "imslp_insert_in_setlist", Description: "Insert a new score immediately after a given previous score in a setlist."}, s.toolInsertInSetlist)
	mcp.AddTool(srv, &mcp.Tool{Name: "imslp_reorder_setlist", Description: "Provide the complete new ordered list of score IDs for a setlist (reorders or changes membership)."}, s.toolReorderSetlist)

	// scores
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_search_scores",
		Description: "Search your library for scores matching the query (any of Work Title, Composer, Title, or other info fields).",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.toolSearchScores)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_show_score",
		Description: "Show rich metadata for a single score (by ID or Work Title). On ambiguous names returns candidates in the error.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.toolShowScore)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "imslp_get_score_download",
		Description: "Return the direct public stor.imslp.org download URL (and title) for a score by ID or Work Title.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.toolGetScoreDownload)

	return srv
}

func mustIMSLPClient(req *mcp.CallToolRequest) (*Client, error) {
	if req.Extra == nil || req.Extra.TokenInfo == nil {
		return nil, fmt.Errorf("no authentication context (MCP authorization required)")
	}
	tok := IMSLPLoginTokenFromTokenInfo(req.Extra.TokenInfo)
	if tok == "" {
		return nil, fmt.Errorf("authenticated but no imslp_login_token present in token")
	}
	return NewClientWithToken(tok), nil
}

// --- Tool implementations ---

type emptyArgs struct{}

func (s *imslpMCPServer) toolWhoami(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	data, err := cli.SyncGet(0, 0, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("sync failed: %w", err)
	}
	if items, ok := data["items"].([]any); ok {
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				if iid, _ := m["itemId"].(string); strings.HasPrefix(iid, "SHAREUSER") {
					if d, ok := m["data"].(map[string]any); ok {
						username, _ := d["username"].(string)
						uid := m["userId"]
						text := fmt.Sprintf("Logged into IMSLP as %q (userId=%v) via MCP OAuth JWT.", username, uid)
						return &mcp.CallToolResult{
							Content: []mcp.Content{&mcp.TextContent{Text: text}},
						}, map[string]any{"username": username, "user_id": uid}, nil
					}
				}
			}
		}
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Authenticated to IMSLP (no SHAREUSER record in initial sync page)."}}}, nil, nil
}

func (s *imslpMCPServer) toolListSetlists(ctx context.Context, req *mcp.CallToolRequest, _ emptyArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	items, _, _, _, err := cli.FetchCurrentState()
	if err != nil {
		return nil, nil, err
	}
	// mimic the CLI `imslpcli setlist list` output: count + nice table
	var lines []string
	lines = append(lines, "ID|NAME|ITEMS")
	var summaries []map[string]any
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			if t, _ := m["type"].(float64); int(t) == 1 {
				data := getMap(m, "data")
				id := getString(m, "itemId")
				name := getString(data, "name")
				n := len(getAnySlice(data, "items"))
				lines = append(lines, fmt.Sprintf("%s|%s|%d", id, name, n))
				summaries = append(summaries, map[string]any{
					"id":    id,
					"name":  name,
					"items": n,
				})
			}
		}
	}
	table := columnize.SimpleFormat(lines)
	text := fmt.Sprintf("%d setlists:\n%s", len(summaries), table)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, summaries, nil
}

type searchSetlistsArgs struct {
	Query string `json:"query" jsonschema:"case-insensitive substring to match against setlist names"`
}

func (s *imslpMCPServer) toolSearchSetlists(ctx context.Context, req *mcp.CallToolRequest, args searchSetlistsArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	results, err := cli.SearchSetlists(args.Query)
	if err != nil {
		return nil, nil, err
	}
	b, _ := json.MarshalIndent(results, "", "  ")
	if len(results) == 0 {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "no matches"}}}, results, nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, results, nil
}

type refArgs struct {
	Setlist string `json:"setlist" jsonschema:"setlist ID or exact name"`
}

func (s *imslpMCPServer) toolShowSetlist(ctx context.Context, req *mcp.CallToolRequest, args refArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	allItems, _, _, _, err := cli.FetchCurrentState()
	if err != nil {
		return nil, nil, err
	}
	var setlist map[string]any
	trimmed := strings.TrimSpace(args.Setlist)
	for _, it := range allItems {
		if m, ok := it.(map[string]any); ok {
			if t, _ := m["type"].(float64); int(t) == 1 {
				data := getMap(m, "data")
				if getString(m, "itemId") == args.Setlist || strings.TrimSpace(getString(data, "name")) == trimmed {
					setlist = m
					break
				}
			}
		}
	}
	if setlist == nil {
		return nil, nil, fmt.Errorf("no setlist found with id or name %q", args.Setlist)
	}
	data := getMap(setlist, "data")
	name := getString(data, "name")
	id := getString(setlist, "itemId")
	scoreIDs := getAnySlice(data, "items")

	// build title map for scores
	scoreTitles := map[string]string{}
	for _, it := range allItems {
		if m, ok := it.(map[string]any); ok {
			if t, _ := m["type"].(float64); int(t) == 0 {
				sid := getString(m, "itemId")
				sdata := getMap(m, "data")
				for _, infIface := range getAnySlice(sdata, "info") {
					inf, ok := infIface.([]any)
					if !ok || len(inf) < 2 {
						continue
					}
					if strings.ToLower(fmt.Sprintf("%v", inf[0])) == "work title" {
						scoreTitles[sid] = fmt.Sprintf("%v", inf[1])
						break
					}
				}
			}
		}
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("Setlist %s (%s) — %d scores", name, id, len(scoreIDs)))
	for _, sidIface := range scoreIDs {
		sid := fmt.Sprintf("%v", sidIface)
		title := scoreTitles[sid]
		if title == "" {
			title = "(title not found)"
		}
		lines = append(lines, fmt.Sprintf("  %s  %s", sid, title))
	}
	text := strings.Join(lines, "\n")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, setlist, nil
}

type createSetlistArgs struct {
	Name     string   `json:"name" jsonschema:"required, name for the new setlist"`
	ScoreIDs []string `json:"score_ids" jsonschema:"optional array of score itemIds to seed the setlist with"`
}

func (s *imslpMCPServer) toolCreateSetlist(ctx context.Context, req *mcp.CallToolRequest, args createSetlistArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	newID, err := cli.CreateSetlist(args.Name, args.ScoreIDs)
	if err != nil {
		return nil, nil, err
	}
	text := fmt.Sprintf("Created setlist %q → %s", args.Name, newID)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, map[string]string{"item_id": newID}, nil
}

type cloneSetlistArgs struct {
	Source  string `json:"source" jsonschema:"source setlist ID or name"`
	NewName string `json:"new_name" jsonschema:"name for the clone"`
}

func (s *imslpMCPServer) toolCloneSetlist(ctx context.Context, req *mcp.CallToolRequest, args cloneSetlistArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	src, err := findSetlist(cli, args.Source)
	if err != nil {
		return nil, nil, err
	}
	newID, err := cli.CloneSetlist(src, args.NewName)
	if err != nil {
		return nil, nil, err
	}
	text := fmt.Sprintf("Cloned %q → new setlist %q (%s)", getString(getMap(src, "data"), "name"), args.NewName, newID)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, map[string]string{"item_id": newID}, nil
}

type renameSetlistArgs struct {
	Setlist string `json:"setlist" jsonschema:"setlist ID or name"`
	NewName string `json:"new_name" jsonschema:"new name"`
}

func (s *imslpMCPServer) toolRenameSetlist(ctx context.Context, req *mcp.CallToolRequest, args renameSetlistArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	cur, err := findSetlist(cli, args.Setlist)
	if err != nil {
		return nil, nil, err
	}
	data := getMap(cur, "data")
	oldItems := getAnySlice(data, "items")
	if err := cli.UpdateSetlist(cur, args.NewName, oldItems); err != nil {
		return nil, nil, err
	}
	text := fmt.Sprintf("Renamed setlist to %q", args.NewName)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

type deleteSetlistArgs struct {
	Setlist string `json:"setlist" jsonschema:"setlist ID or name to delete"`
}

func (s *imslpMCPServer) toolDeleteSetlist(ctx context.Context, req *mcp.CallToolRequest, args deleteSetlistArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	cur, err := findSetlist(cli, args.Setlist)
	if err != nil {
		return nil, nil, err
	}
	name := getString(getMap(cur, "data"), "name")
	if err := cli.DeleteSetlist(cur); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Deleted setlist %q", name)}}}, nil, nil
}

type appendArgs struct {
	Setlist string `json:"setlist" jsonschema:"setlist ID or name"`
	ScoreID string `json:"score_id" jsonschema:"score itemId to append"`
}

func (s *imslpMCPServer) toolAppendToSetlist(ctx context.Context, req *mcp.CallToolRequest, args appendArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	cur, err := findSetlist(cli, args.Setlist)
	if err != nil {
		return nil, nil, err
	}
	if err := cli.AppendToSetlist(cur, args.ScoreID); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Appended %s to setlist", args.ScoreID)}}}, nil, nil
}

type prependArgs struct {
	Setlist string `json:"setlist" jsonschema:"setlist ID or name"`
	ScoreID string `json:"score_id" jsonschema:"score itemId to prepend"`
}

func (s *imslpMCPServer) toolPrependToSetlist(ctx context.Context, req *mcp.CallToolRequest, args prependArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	cur, err := findSetlist(cli, args.Setlist)
	if err != nil {
		return nil, nil, err
	}
	if err := cli.PrependToSetlist(cur, args.ScoreID); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Prepended %s to setlist", args.ScoreID)}}}, nil, nil
}

type insertArgs struct {
	Setlist string `json:"setlist" jsonschema:"setlist ID or name"`
	PrevID  string `json:"prev_score_id" jsonschema:"the score after which to insert"`
	NewID   string `json:"new_score_id" jsonschema:"the score to insert"`
}

func (s *imslpMCPServer) toolInsertInSetlist(ctx context.Context, req *mcp.CallToolRequest, args insertArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	cur, err := findSetlist(cli, args.Setlist)
	if err != nil {
		return nil, nil, err
	}
	if err := cli.InsertAfterInSetlist(cur, args.PrevID, args.NewID); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Inserted %s after %s", args.NewID, args.PrevID)}}}, nil, nil
}

type reorderArgs struct {
	Setlist  string   `json:"setlist" jsonschema:"setlist ID or name"`
	ScoreIDs []string `json:"score_ids" jsonschema:"complete new ordered list of score itemIds"`
}

func (s *imslpMCPServer) toolReorderSetlist(ctx context.Context, req *mcp.CallToolRequest, args reorderArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	cur, err := findSetlist(cli, args.Setlist)
	if err != nil {
		return nil, nil, err
	}
	data := getMap(cur, "data")
	oldName := getString(data, "name")
	ids := make([]any, len(args.ScoreIDs))
	for i, v := range args.ScoreIDs {
		ids[i] = v
	}
	if err := cli.UpdateSetlist(cur, oldName, ids); err != nil {
		return nil, nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Reordered setlist %q", oldName)}}}, nil, nil
}

type searchScoresArgs struct {
	Query string `json:"query" jsonschema:"substring to search in any score info field (title, composer, work title...)"`
}

func (s *imslpMCPServer) toolSearchScores(ctx context.Context, req *mcp.CallToolRequest, args searchScoresArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	results, err := cli.SearchScores(args.Query)
	if err != nil {
		return nil, nil, err
	}
	b, _ := json.MarshalIndent(results, "", "  ")
	if len(results) == 0 {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "no matches"}}}, results, nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, results, nil
}

type scoreRefArgs struct {
	IDOrName string `json:"id_or_name" jsonschema:"score itemId or exact Work Title"`
}

func (s *imslpMCPServer) toolShowScore(ctx context.Context, req *mcp.CallToolRequest, args scoreRefArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	score, err := findScore(cli, args.IDOrName)
	if err != nil {
		return nil, nil, err
	}
	data := getMap(score, "data")
	custom := getMap(data, "custom")
	itemID := getString(score, "itemId")

	var entries []struct{ key, val string }
	entries = append(entries, struct{ key, val string }{"ID", itemID})
	for _, k := range []string{"createdAt", "updatedAt", "revision", "userId", "type", "isDeleted", "fileItemId"} {
		raw := score[k]
		v := fmt.Sprintf("%v", raw)
		if f, ok := raw.(float64); ok {
			if f == float64(int64(f)) {
				v = fmt.Sprintf("%d", int64(f))
			} else {
				v = fmt.Sprintf("%.0f", f)
			}
		}
		if v == "<nil>" {
			v = "(null)"
		}
		entries = append(entries, struct{ key, val string }{k, v})
	}
	for _, infIface := range getAnySlice(data, "info") {
		inf, ok := infIface.([]any)
		if !ok || len(inf) < 2 {
			continue
		}
		k := fmt.Sprintf("%v", inf[0])
		v := fmt.Sprintf("%v", inf[1])
		entries = append(entries, struct{ key, val string }{k, v})
	}
	for _, ck := range []string{"fileHash", "downloadURL", "filePath"} {
		cv := getString(custom, ck)
		entries = append(entries, struct{ key, val string }{ck, cv})
	}
	fileHash := getString(custom, "fileHash")
	stor := "(unavailable)"
	if len(fileHash) >= 3 {
		stor = fmt.Sprintf("https://stor.imslp.org/uploads/shared/%s/%s/%s/%s.pdf", fileHash[0:1], fileHash[1:2], fileHash[2:3], fileHash)
	}
	entries = append(entries, struct{ key, val string }{"Download URL", stor})

	var lines []string
	for _, e := range entries {
		lines = append(lines, fmt.Sprintf("%s: %s", e.key, e.val))
	}
	text := strings.Join(lines, "\n")
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, score, nil
}

func (s *imslpMCPServer) toolGetScoreDownload(ctx context.Context, req *mcp.CallToolRequest, args scoreRefArgs) (*mcp.CallToolResult, any, error) {
	cli, err := mustIMSLPClient(req)
	if err != nil {
		return nil, nil, err
	}
	score, err := findScore(cli, args.IDOrName)
	if err != nil {
		return nil, nil, err
	}
	data := getMap(score, "data")
	custom := getMap(data, "custom")
	downloadURL := getString(custom, "downloadURL")
	title := ""
	for _, infIface := range getAnySlice(data, "info") {
		inf, ok := infIface.([]any)
		if !ok || len(inf) < 2 {
			continue
		}
		if strings.ToLower(fmt.Sprintf("%v", inf[0])) == "work title" {
			title = fmt.Sprintf("%v", inf[1])
			break
		}
	}
	if title == "" {
		title = getString(score, "itemId")
	}
	if downloadURL == "" {
		fh := getString(custom, "fileHash")
		if fh != "" && len(fh) >= 3 {
			downloadURL = fmt.Sprintf("https://stor.imslp.org/uploads/shared/%s/%s/%s/%s.pdf", fh[0:1], fh[1:2], fh[2:3], fh)
		}
	}
	text := fmt.Sprintf("%s\nDirect download URL (public, no auth): %s", title, downloadURL)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, map[string]string{"title": title, "download_url": downloadURL, "id": getString(score, "itemId")}, nil
}
