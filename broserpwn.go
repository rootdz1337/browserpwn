// scannerweb.go
//
// Automated browser-driven bug scanner. Loads a site in headless Chrome,
// exercises the UI, intercepts network traffic, executes JS, and correlates
// findings from all passive + active scanners.
//
// Requires:
//   go get github.com/chromedp/chromedp
//   go get github.com/chromedp/cdproto
package scannerweb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// =============================================================================
// Public types
// =============================================================================

// Config controls the scanner.
type Config struct {
	ChromePath   string
	Timeout      time.Duration
	MaxPages     int
	MaxDepth     int
	Headless     bool
	NoSandbox    bool
	UserAgent    string
	Proxy        string
	SubmitForms  bool
	ExecuteJS    bool
	SnapshotHTML bool
	// ReflectionMarker is the unique string sent in probe params to detect
	// reflection. Default: "scannerweb_reflect_9283".
	ReflectionMarker string
}

// Report is the aggregated output.
type Report struct {
	Target        string
	FinalURL      string
	Title         string
	Status        int
	Took          time.Duration
	Pages         []PageFinding
	Network       NetworkSummary
	Console       []ConsoleMessage
	Cookies       []CookieFinding
	Forms         []FormInfo
	JSFindings    []JSFinding
	Storage       StorageFindings
	DOMIssues     []DOMFinding
	MixedContent  []string
	PostMessage   []PostMessageFinding
	Sinks         []SinkFinding
	WebSockets    []WebSocketFinding
	CSPViolations []CSPViolation
	Reflections   []ReflectionFinding
	Errors        []string
}

type PageFinding struct {
	URL       string
	Title     string
	Status    int
	Depth     int
	Links     []string
	Resources []Resource
	HTMLHash  string
	Took      time.Duration
}

type Resource struct {
	URL       string
	Type      string
	Method    string
	Status    int
	MIME      string
	Size      int64
	FromCache bool
	Headers   map[string]string
}

type NetworkSummary struct {
	TotalRequests  int
	UniqueHosts    []string
	ThirdParties   []string
	Insecure       []string
	LargeResponses []Resource
	Errors4xx      []Resource
	Errors5xx      []Resource
	XHRFindings    []XHRFinding
}

type XHRFinding struct {
	URL          string
	Method       string
	Status       int
	Note         string
	ResponseHead map[string]string
}

type ConsoleMessage struct {
	Type string
	Text string
	URL  string
	Line int
}

type CookieFinding struct {
	Name      string
	Domain    string
	Path      string
	Secure    bool
	HTTPOnly  bool
	SameSite  string
	Session   bool
	Expires   string
	Source    string // "set-cookie" | "js-visible"
	Issues    []string
}

type FormInfo struct {
	Action     string
	Method     string
	Fields     []FormField
	HasCSRF    bool
	HasCaptcha bool
	PageURL    string
}

type FormField struct {
	Name  string
	Type  string
	Value string
}

type JSFinding struct {
	Rule     string
	Severity string
	URL      string
	Detail   string
	Snippet  string
}

type StorageFindings struct {
	LocalStorage   map[string]string
	SessionStorage map[string]string
	IndexedDB      map[string][]string
	Cookies        map[string]string
	Issues         []string
}

type DOMFinding struct {
	Rule     string
	Severity string
	URL      string
	Element  string
	Detail   string
}

// PostMessageFinding captures window.postMessage security issues.
type PostMessageFinding struct {
	Rule     string
	Severity string
	URL      string
	Detail   string
	Snippet  string
}

// SinkFinding is a dangerous JS API usage (source or sink).
type SinkFinding struct {
	Rule     string
	Severity string
	URL      string
	Line     int
	Snippet  string
	Detail   string
	Kind     string // "source" | "sink" | "both"
}

// WebSocketFinding captures WS-related issues.
type WebSocketFinding struct {
	Rule     string
	Severity string
	URL      string
	WSURL    string
	Detail   string
}

// CSPViolation is a captured Content-Security-Policy violation.
type CSPViolation struct {
	URL            string
	BlockedURI     string
	ViolatedDirective string
	EffectiveDirective string
	OriginalPolicy string
	Disposition    string // "enforce" | "report"
	SourceFile     string
	Line           int
}

// ReflectionFinding is a reflected parameter in JS context.
type ReflectionFinding struct {
	URL      string
	Param    string
	Context  string // "html" | "script" | "attr" | "url"
	Snippet  string
	Severity string
}

// =============================================================================
// Scanner
// =============================================================================

type Scanner struct {
	cfg      Config
	allocCtx context.Context
	cancel   context.CancelFunc
}

func New(cfg Config) (*Scanner, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if cfg.MaxPages == 0 {
		cfg.MaxPages = 50
	}
	if cfg.MaxDepth == 0 {
		cfg.MaxDepth = 3
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
			"(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 ScannerWeb/1.0"
	}
	if cfg.ReflectionMarker == "" {
		cfg.ReflectionMarker = "scannerweb_reflect_9283"
	}
	if !cfg.Headless {
		cfg.Headless = true
	}
	if !cfg.ExecuteJS {
		cfg.ExecuteJS = true
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", cfg.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-component-update", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("excludeSwitches", "enable-automation"),
		chromedp.UserAgent(cfg.UserAgent),
	)
	if cfg.NoSandbox {
		opts = append(opts, chromedp.Flag("no-sandbox", true))
	}
	if cfg.ChromePath != "" {
		opts = append(opts, chromedp.ExecPath(cfg.ChromePath))
	}
	if cfg.Proxy != "" {
		opts = append(opts, chromedp.ProxyServer(cfg.Proxy))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	return &Scanner{cfg: cfg, allocCtx: allocCtx, cancel: cancel}, nil
}

func (s *Scanner) Close() {
	if s.cancel != nil {
		s.cancel()
	}
}

// =============================================================================
// Main entry point
// =============================================================================

func (s *Scanner) Scan(ctx context.Context, target string) (*Report, error) {
	start := time.Now()
	rep := &Report{Target: target}

	tabCtx, tabCancel := chromedp.NewContext(s.allocCtx)
	defer tabCancel()

	if err := chromedp.Run(tabCtx); err != nil {
		return nil, fmt.Errorf("start browser: %w", err)
	}

	// Shared accumulators.
	var (
		mu           sync.Mutex
		network_     NetworkSummary
		console_     []ConsoleMessage
		cookies_     []CookieFinding
		forms_       []FormInfo
		jsFinds      []JSFinding
		domFinds     []DOMFinding
		pmFinds      []PostMessageFinding
		sinkFinds    []SinkFinding
		wsFinds      []WebSocketFinding
		cspViols     []CSPViolation
		reflectFinds []ReflectionFinding
		storage      = StorageFindings{
			LocalStorage:   map[string]string{},
			SessionStorage: map[string]string{},
			IndexedDB:      map[string][]string{},
			Cookies:        map[string]string{},
		}
		hosts        = map[string]bool{}
		thirdParties = map[string]bool{}
		mixedContent = map[string]bool{}
		pageHTML     = map[string]string{}
		seenCookies  = map[string]bool{}
	)

	// Attach network / runtime / console / CSP listeners.
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		mu.Lock()
		defer mu.Unlock()
		switch e := ev.(type) {

		case *network.EventRequestWillBeSent:
			network_.TotalRequests++
			if u, err := url.Parse(e.Request.URL); err == nil {
				hosts[u.Host] = true
				if !strings.Contains(target, u.Host) && u.Host != "" {
					thirdParties[u.Host] = true
				}
			}
			if strings.HasPrefix(e.DocumentURL, "https://") && strings.HasPrefix(e.Request.URL, "http://") {
				mixedContent[e.Request.URL] = true
			}
			// WebSocket handshake.
			if strings.EqualFold(e.Request.URL, "") == false &&
				(strings.HasPrefix(e.Request.URL, "ws://") || strings.HasPrefix(e.Request.URL, "wss://")) {
				wsFinds = append(wsFinds, analyzeWebSocketRequest(e.Request.URL, e.DocumentURL))
			}

		case *network.EventResponseReceived:
			r := Resource{
				URL:    e.Response.URL,
				Type:   string(e.Type),
				Status: int(e.Response.Status),
				MIME:   e.Response.MimeType,
			}
			if e.Response.FromDiskCache || e.Response.FromPrefetchCache {
				r.FromCache = true
			}
			if r.Status >= 500 {
				network_.Errors5xx = append(network_.Errors5xx, r)
			} else if r.Status >= 400 && r.Status != 404 {
				network_.Errors4xx = append(network_.Errors4xx, r)
			}
			if r.Type == "XHR" || r.Type == "Fetch" {
				note := ""
				lm := strings.ToLower(r.MIME)
				if r.Status == 200 && strings.Contains(lm, "json") {
					note = "JSON response"
				}
				if strings.Contains(r.URL, "graphql") {
					note = "GraphQL endpoint"
				}
				if note != "" {
					network_.XHRFindings = append(network_.XHRFindings, XHRFinding{
						URL: r.URL, Status: r.Status, Note: note,
					})
				}
			}

		case *network.EventWebSocketCreated:
			wsFinds = append(wsFinds, analyzeWebSocketRequest(e.URL, e.Initiator.URL))

		case *runtime.EventConsoleAPICalled:
			msg := ConsoleMessage{Type: string(e.Type)}
			for _, arg := range e.Args {
				if arg.Value != nil {
					var s string
					if err := json.Unmarshal(arg.Value, &s); err == nil {
						msg.Text += s + " "
					} else {
						msg.Text += string(arg.Value) + " "
					}
				}
			}
			if e.StackTrace != nil {
				for _, f := range e.StackTrace.CallFrames {
					msg.URL = f.URL
					msg.Line = int(f.LineNumber)
					break
				}
			}
			console_ = append(console_, msg)

		case *runtime.EventExceptionThrown:
			d := e.ExceptionDetails
			console_ = append(console_, ConsoleMessage{
				Type: "exception", Text: d.Text,
				URL: func() string {
					if d.URL != "" {
						return d.URL
					}
					if d.StackTrace != nil && len(d.StackTrace.CallFrames) > 0 {
						return d.StackTrace.CallFrames[0].URL
					}
					return ""
				}(),
				Line: int(d.LineNumber),
			})
		}
	})

	// Enable domains.
	if err := chromedp.Run(tabCtx,
		network.Enable(),
		runtime.Enable(),
		page.Enable(),
	); err != nil {
		return nil, fmt.Errorf("enable domains: %w", err)
	}

	// Inject the CSP violation listener + WebSocket hook + postMessage hook
	// into every page via Page.addScriptToEvaluateOnNewDocument.
	bootstrapJS := `(function(){
		// --- CSP violation capture ---
		document.addEventListener('securitypolicyviolation', function(ev){
			window.__scannerweb_csp = window.__scannerweb_csp || [];
			window.__scannerweb_csp.push({
				blockedURI: ev.blockedURI,
				violatedDirective: ev.violatedDirective,
				effectiveDirective: ev.effectiveDirective,
				originalPolicy: ev.originalPolicy,
				disposition: ev.disposition,
				sourceFile: ev.sourceFile || '',
				lineNumber: ev.lineNumber || 0,
				documentURI: ev.documentURI
			});
		});

		// --- WebSocket tracking ---
		var NativeWS = window.WebSocket;
		if (NativeWS) {
			window.__scannerweb_ws = [];
			window.WebSocket = function(url, protocols) {
				try {
					window.__scannerweb_ws.push({
						url: String(url),
						protocols: protocols || null,
						stack: (new Error()).stack || ''
					});
				} catch(e){}
				return new NativeWS(url, protocols);
			};
			window.WebSocket.prototype = NativeWS.prototype;
			Object.assign(window.WebSocket, NativeWS);
		}

		// --- postMessage listener tracking ---
		var nativeAdd = window.addEventListener;
		window.__scannerweb_pm_listeners = [];
		window.addEventListener = function(type, listener, opts) {
			if (type === 'message' && typeof listener === 'function') {
				try {
					window.__scannerweb_pm_listeners.push({
						source: listener.toString().slice(0, 2000),
						stack: (new Error()).stack || ''
					});
				} catch(e){}
			}
			return nativeAdd.apply(this, [type, listener, opts]);
		};

		// --- Error/exception hooks ---
		window.__scannerweb_errors = [];
		window.addEventListener('error', function(e){
			window.__scannerweb_errors.push({msg: e.message, src: e.filename, line: e.lineno});
		});
		window.addEventListener('unhandledrejection', function(e){
			window.__scannerweb_errors.push({msg: 'unhandledrejection: ' + String(e.reason), src: '', line: 0});
		});
	})();`
	if err := chromedp.Run(tabCtx, page.AddScriptToEvaluateOnNewDocument(bootstrapJS)); err != nil {
		// Non-fatal — some environments disallow the script.
		rep.Errors = append(rep.Errors, "bootstrap inject: "+err.Error())
	}

	// BFS crawl.
	visited := &visitTracker{seen: map[string]bool{}}
	queue := []crawlItem{{url: target, depth: 0}}

	for len(queue) > 0 && len(visited.seen) < s.cfg.MaxPages {
		if ctx.Err() != nil {
			break
		}
		item := queue[0]
		queue = queue[1:]
		if visited.add(item.url) {
			continue
		}

		pageStart := time.Now()
		pf, links, err := s.crawlPage(tabCtx, item, visited,
			&mu, &pageHTML, &forms_, &cookies_, &seenCookies,
			&jsFinds, &domFinds, &pmFinds, &sinkFinds, &wsFinds,
			&cspViols, &reflectFinds, &storage, &console_)
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", item.url, err))
			continue
		}
		pf.Took = time.Since(pageStart)
		rep.Pages = append(rep.Pages, *pf)

		if len(rep.Pages) == 1 {
			rep.FinalURL = pf.URL
			rep.Title = pf.Title
			rep.Status = pf.Status
		}

		if item.depth < s.cfg.MaxDepth {
			for _, l := range links {
				if !visited.seen[l] {
					queue = append(queue, crawlItem{url: l, depth: item.depth + 1})
				}
			}
		}
	}

	// Flush captured CSP violations + WS + errors from the last page.
	s.collectBootstrapFindings(tabCtx, rep.FinalURL, &mu,
		&cspViols, &wsFinds, &console_, &pmFinds, &reflectFinds)

	// Finalize.
	mu.Lock()
	network_.UniqueHosts = keys(hosts)
	network_.ThirdParties = keys(thirdParties)
	network_.Insecure = keys(mixedContent)
	rep.Network = network_
	rep.Console = console_
	rep.Cookies = cookies_
	rep.Forms = forms_
	rep.JSFindings = jsFinds
	rep.DOMIssues = domFinds
	rep.Storage = storage
	rep.MixedContent = keys(mixedContent)
	rep.PostMessage = pmFinds
	rep.Sinks = sinkFinds
	rep.WebSockets = wsFinds
	rep.CSPViolations = cspViols
	rep.Reflections = reflectFinds
	mu.Unlock()

	sort.Slice(rep.Pages, func(i, j int) bool { return rep.Pages[i].URL < rep.Pages[j].URL })
	sort.Slice(rep.Sinks, func(i, j int) bool { return sevRank(rep.Sinks[i].Severity) < sevRank(rep.Sinks[j].Severity) })
	sort.Slice(rep.PostMessage, func(i, j int) bool { return sevRank(rep.PostMessage[i].Severity) < sevRank(rep.PostMessage[j].Severity) })
	sort.Slice(rep.WebSockets, func(i, j int) bool { return sevRank(rep.WebSockets[i].Severity) < sevRank(rep.WebSockets[j].Severity) })
	sort.Slice(rep.Reflections, func(i, j int) bool { return sevRank(rep.Reflections[i].Severity) < sevRank(rep.Reflections[j].Severity) })

	rep.Took = time.Since(start)
	return rep, nil
}

type crawlItem struct {
	url   string
	depth int
}

type visitTracker struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (v *visitTracker) add(u string) bool {
	if parsed, err := url.Parse(u); err == nil {
		parsed.Fragment = ""
		u = parsed.String()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen[u] {
		return true
	}
	v.seen[u] = true
	return false
}

// =============================================================================
// Per-page crawl
// =============================================================================

func (s *Scanner) crawlPage(ctx context.Context, item crawlItem, visited *visitTracker, mu *sync.Mutex,
	pageHTML *map[string]string, forms *[]FormInfo, cookies *[]CookieFinding, seenCookies *map[string]bool,
	jsFinds *[]JSFinding, domFinds *[]DOMFinding, pmFinds *[]PostMessageFinding,
	sinkFinds *[]SinkFinding, wsFinds *[]WebSocketFinding, cspViols *[]CSPViolation,
	reflectFinds *[]ReflectionFinding, storage *StorageFindings, console *[]ConsoleMessage) (*PageFinding, []string, error) {

	pctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	pf := &PageFinding{URL: item.url, Depth: item.depth}

	var title, html, finalURL string
	var status int64
	err := chromedp.Run(pctx,
		chromedp.Navigate(item.url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Title(&title),
		chromedp.Location(&finalURL),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
		chromedp.Evaluate(`performance.getEntriesByType("navigation")[0]?.responseStatus || 0`, &status),
	)
	if err != nil {
		return nil, nil, err
	}
	pf.URL = finalURL
	pf.Title = title
	pf.Status = int(status)
	pf.HTMLHash = sha256Hex(html)

	mu.Lock()
	(*pageHTML)[finalURL] = html
	mu.Unlock()

	// DOM extraction.
	links, formsOnPage, err := s.extractDOM(pctx, finalURL)
	if err == nil {
		pf.Links = links
		mu.Lock()
		*forms = append(*forms, formsOnPage...)
		mu.Unlock()
	}

	// Cookie capture — CDP authoritative + document.cookie supplement.
	if err := s.captureCookies(pctx, finalURL, cookies, seenCookies, mu); err != nil {
		// non-fatal
	}

	if s.cfg.ExecuteJS {
		// Framework / globals.
		if js, dom, err := s.runJSProbes(pctx, finalURL); err == nil {
			mu.Lock()
			*jsFinds = append(*jsFinds, js...)
			*domFinds = append(*domFinds, dom...)
			mu.Unlock()
		}

		// NEW: Sink detection.
		if sinks, err := s.detectSinks(pctx, finalURL); err == nil {
			mu.Lock()
			*sinkFinds = append(*sinkFinds, sinks...)
			mu.Unlock()
		}

		// NEW: postMessage handler audit.
		if pm, err := s.auditPostMessage(pctx, finalURL); err == nil {
			mu.Lock()
			*pmFinds = append(*pmFinds, pm...)
			mu.Unlock()
		}

		// NEW: WebSocket instances.
		if ws, err := s.detectWebSockets(pctx, finalURL); err == nil {
			mu.Lock()
			*wsFinds = append(*wsFinds, ws...)
			mu.Unlock()
		}

		// NEW: CSP violations captured by the injected listener.
		if v, err := s.collectCSPViolations(pctx, finalURL); err == nil {
			mu.Lock()
			*cspViols = append(*cspViols, v...)
			mu.Unlock()
		}

		// Storage.
		ls, ss, err := s.dumpStorage(pctx)
		if err == nil {
			mu.Lock()
			for k, v := range ls {
				storage.LocalStorage[k] = v
			}
			for k, v := range ss {
				storage.SessionStorage[k] = v
			}
			mu.Unlock()
		}
	}

	// Form reflection probes (with marker param).
	if s.cfg.SubmitForms {
		for _, f := range formsOnPage {
			if strings.EqualFold(f.Method, "GET") && !f.HasCSRF {
				formURL := buildFormURL(finalURL, f, s.cfg.ReflectionMarker)
				if formURL == "" {
					continue
				}
				if r := s.probeReflection(pctx, formURL, s.cfg.ReflectionMarker); r != nil {
					mu.Lock()
					*reflectFinds = append(*reflectFinds, *r)
					mu.Unlock()
				}
			}
		}
	}

	return pf, links, nil
}

// =============================================================================
// DOM extraction
// =============================================================================

func (s *Scanner) extractDOM(ctx context.Context, pageURL string) ([]string, []FormInfo, error) {
	var linksJSON, formsJSON string

	linkScript := `JSON.stringify(
		Array.from(document.querySelectorAll('a[href]'))
			.map(a => a.href)
			.filter(h => h && (h.startsWith('http://') || h.startsWith('https://')))
			.filter((v, i, arr) => arr.indexOf(v) === i)
	)`
	if err := chromedp.Run(ctx, chromedp.Evaluate(linkScript, &linksJSON)); err != nil {
		return nil, nil, err
	}
	var links []string
	_ = json.Unmarshal([]byte(linksJSON), &links)

	formScript := `JSON.stringify(
		Array.from(document.querySelectorAll('form')).map(f => ({
			action: f.action || location.href,
			method: (f.method || 'GET').toUpperCase(),
			fields: Array.from(f.querySelectorAll('input,select,textarea'))
				.map(i => ({name: i.name, type: i.type, value: i.value || ''}))
				.filter(i => i.name),
			hasCSRF: !!f.querySelector('input[name*="csrf" i], input[name*="token" i]'),
			hasCaptcha: !!f.querySelector('[class*="captcha" i], [id*="captcha" i], [name*="captcha" i]')
		}))
	)`
	if err := chromedp.Run(ctx, chromedp.Evaluate(formScript, &formsJSON)); err != nil {
		return links, nil, err
	}
	var rawForms []struct {
		Action string `json:"action"`
		Method string `json:"method"`
		Fields []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"fields"`
		HasCSRF    bool `json:"hasCSRF"`
		HasCaptcha bool `json:"hasCaptcha"`
	}
	_ = json.Unmarshal([]byte(formsJSON), &rawForms)
	var forms []FormInfo
	for _, rf := range rawForms {
		fi := FormInfo{Action: rf.Action, Method: rf.Method, HasCSRF: rf.HasCSRF, HasCaptcha: rf.HasCaptcha, PageURL: pageURL}
		for _, f := range rf.Fields {
			fi.Fields = append(fi.Fields, FormField{Name: f.Name, Type: f.Type, Value: f.Value})
		}
		forms = append(forms, fi)
	}
	return links, forms, nil
}

// =============================================================================
// Cookie capture — CDP authoritative + document.cookie
// =============================================================================

func (s *Scanner) captureCookies(ctx context.Context, pageURL string, cookies *[]CookieFinding, seen *map[string]bool, mu *sync.Mutex) error {
	// 1. CDP — authoritative (includes HttpOnly, Secure, SameSite).
	cdpCookies, err := network.GetAllCookies().Do(ctx)
	if err == nil {
		mu.Lock()
		for _, c := range cdpCookies {
			key := c.Domain + "|" + c.Path + "|" + c.Name
			if (*seen)[key] {
				continue
			}
			(*seen)[key] = true

			cf := CookieFinding{
				Name:     c.Name,
				Domain:   c.Domain,
				Path:     c.Path,
				Secure:   c.Secure,
				HTTPOnly: c.HTTPOnly,
				Session:  c.Session,
				Expires:  fmt.Sprintf("%.0f", c.Expires),
				SameSite: string(c.SameSite),
				Source:   "set-cookie",
			}
			// Issue detection.
			if !c.HTTPOnly {
				cf.Issues = append(cf.Issues, "missing HttpOnly — accessible via document.cookie")
			}
			if !c.Secure && strings.HasPrefix(pageURL, "https://") {
				cf.Issues = append(cf.Issues, "missing Secure on HTTPS site")
			}
			if strings.EqualFold(string(c.SameSite), "None") && !c.Secure {
				cf.Issues = append(cf.Issues, "SameSite=None without Secure (browser rejects)")
			}
			if c.SameSite == "" && !c.Secure {
				cf.Issues = append(cf.Issues, "no SameSite + no Secure")
			}
			// Session cookie on sensitive name.
			lname := strings.ToLower(c.Name)
			if (strings.Contains(lname, "sess") || strings.Contains(lname, "auth") ||
				strings.Contains(lname, "token") || lname == "sid" || lname == "jsessionid") && !c.HTTPOnly {
				cf.Issues = append(cf.Issues, "session-like cookie without HttpOnly — XSS session theft risk")
			}
			// Over-long expiry.
			if c.Expires > 0 && time.Now().Unix()+31536000 < int64(c.Expires) {
				cf.Issues = append(cf.Issues, "expiry > 1 year")
			}
			// Wildcard domain.
			if strings.HasPrefix(c.Domain, ".") && len(strings.Split(c.Domain, ".")) == 2 {
				cf.Issues = append(cf.Issues, "wildcard TLD-wide domain")
			}
			*cookies = append(*cookies, cf)
		}
		mu.Unlock()
	}

	// 2. document.cookie — reveals JS-visible cookies (missing HttpOnly).
	var jsCookiesJSON string
	if err := chromedp.Run(ctx, chromedp.Evaluate(
		`JSON.stringify(document.cookie.split(';').map(c=>c.trim()).filter(Boolean))`, &jsCookiesJSON)); err == nil {
		var jsCookies []string
		_ = json.Unmarshal([]byte(jsCookiesJSON), &jsCookies)
		mu.Lock()
		for _, c := range jsCookies {
			parts := strings.SplitN(c, "=", 2)
			if len(parts) < 2 {
				continue
			}
			name := strings.TrimSpace(parts[0])
			key := "js|" + name
			if (*seen)[key] {
				continue
			}
			(*seen)[key] = true
			*cookies = append(*cookies, CookieFinding{
				Name:    name,
				Source:  "js-visible",
				HTTPOnly: false,
				Issues:  []string{"visible to document.cookie — no HttpOnly"},
			})
		}
		mu.Unlock()
	}
	return nil
}

// =============================================================================
// Framework / globals probes
// =============================================================================

func (s *Scanner) runJSProbes(ctx context.Context, pageURL string) ([]JSFinding, []DOMFinding, error) {
	var jsFinds []JSFinding
	var domFinds []DOMFinding

	globalsScript := `JSON.stringify({
		angular: typeof angular !== 'undefined',
		react: typeof React !== 'undefined' || !!document.querySelector('[data-reactroot],#___gatsby,#root'),
		vue: typeof Vue !== 'undefined' || !!document.querySelector('[data-v-app],#__nuxt'),
		jquery: typeof jQuery !== 'undefined',
		backbone: typeof Backbone !== 'undefined',
		ember: typeof Ember !== 'undefined',
		knockout: typeof ko !== 'undefined',
		requirejs: typeof require !== 'undefined',
		sentry: typeof Sentry !== 'undefined',
		googleAnalytics: typeof ga !== 'undefined' || typeof gtag !== 'undefined',
		gtm: !!window.dataLayer,
		serviceWorker: 'serviceWorker' in navigator,
		debugMode: !!window.DEBUG || !!window.__DEV__,
		leaked: Object.keys(window).filter(k => /^(api|secret|token|auth|key|debug)/i.test(k) && typeof window[k] === 'string')
	})`
	var globalsJSON string
	if err := chromedp.Run(ctx, chromedp.Evaluate(globalsScript, &globalsJSON)); err != nil {
		return nil, nil, err
	}
	var globals map[string]interface{}
	_ = json.Unmarshal([]byte(globalsJSON), &globals)

	if leaked, ok := globals["leaked"].([]interface{}); ok {
		for _, l := range leaked {
			if name, ok := l.(string); ok {
				jsFinds = append(jsFinds, JSFinding{
					Rule: "globals_sensitive_window_var", Severity: "medium", URL: pageURL,
					Detail: fmt.Sprintf("window.%s is a string and may leak secrets", name)})
			}
		}
	}
	if dbg, ok := globals["debugMode"].(bool); ok && dbg {
		jsFinds = append(jsFinds, JSFinding{
			Rule: "debug_mode", Severity: "low", URL: pageURL,
			Detail: "window.DEBUG or window.__DEV__ truthy — production may be dev build"})
	}
	for _, fw := range []string{"angular", "react", "vue", "jquery", "backbone", "ember", "knockout", "requirejs"} {
		if v, ok := globals[fw].(bool); ok && v {
			jsFinds = append(jsFinds, JSFinding{
				Rule: "framework_" + fw, Severity: "info", URL: pageURL,
				Detail: fw + " detected"})
		}
	}

	domScript := `JSON.stringify({
		missingSRI: Array.from(document.querySelectorAll('script[src],link[rel="stylesheet"][href]'))
			.filter(el => !el.integrity).map(el => el.src || el.href)
			.filter(u => /^https?:/i.test(u)).filter((v,i,a)=>a.indexOf(v)===i),
		formAutoComplete: Array.from(document.querySelectorAll('input[type="password"],input[type="email"],input[name*="user" i]'))
			.filter(el => !el.autocomplete || el.autocomplete === 'on')
			.map(el => el.name || el.id || el.type),
		insecureForms: Array.from(document.querySelectorAll('form'))
			.filter(f => f.action && f.action.startsWith('http://') && location.protocol === 'https:')
			.map(f => f.action),
		inlineHandlers: Array.from(document.querySelectorAll('*'))
			.filter(el => Array.from(el.attributes||[]).some(a => /^on/i.test(a.name)))
			.slice(0,20).map(el => el.tagName + ':' + el.outerHTML.slice(0,100)),
		targetBlankNoopener: Array.from(document.querySelectorAll('a[target="_blank"]'))
			.filter(a => !(a.rel||'').toLowerCase().includes('noopener'))
			.map(a => a.href).slice(0,20)
	})`
	var domJSON string
	if err := chromedp.Run(ctx, chromedp.Evaluate(domScript, &domJSON)); err != nil {
		return jsFinds, domFinds, err
	}
	var dom map[string]interface{}
	_ = json.Unmarshal([]byte(domJSON), &dom)

	if arr, ok := dom["missingSRI"].([]interface{}); ok {
		for _, s := range arr {
			if u, ok := s.(string); ok {
				domFinds = append(domFinds, DOMFinding{
					Rule: "missing_sri", Severity: "medium", URL: pageURL,
					Element: u, Detail: "External script/stylesheet without integrity hash"})
			}
		}
	}
	if arr, ok := dom["formAutoComplete"].([]interface{}); ok && len(arr) > 0 {
		domFinds = append(domFinds, DOMFinding{
			Rule: "autocomplete_enabled_on_sensitive", Severity: "low", URL: pageURL,
			Detail: fmt.Sprintf("%d sensitive fields allow autocomplete", len(arr))})
	}
	if arr, ok := dom["insecureForms"].([]interface{}); ok {
		for _, s := range arr {
			if u, ok := s.(string); ok {
				domFinds = append(domFinds, DOMFinding{
					Rule: "insecure_form_action", Severity: "high", URL: pageURL,
					Element: u, Detail: "HTTPS page has form action over HTTP"})
			}
		}
	}
	if arr, ok := dom["inlineHandlers"].([]interface{}); ok && len(arr) > 0 {
		domFinds = append(domFinds, DOMFinding{
			Rule: "inline_event_handlers", Severity: "low", URL: pageURL,
			Detail: fmt.Sprintf("%d elements with inline on* handlers", len(arr))})
	}
	if arr, ok := dom["targetBlankNoopener"].([]interface{}); ok {
		for _, s := range arr {
			if u, ok := s.(string); ok {
				domFinds = append(domFinds, DOMFinding{
					Rule: "target_blank_no_noopener", Severity: "low", URL: pageURL,
					Element: u, Detail: "target=_blank without rel=noopener"})
			}
		}
	}
	return jsFinds, domFinds, nil
}

// =============================================================================
// NEW: Sink detection (static JS analysis)
// =============================================================================

// sinkPatterns are JS API regexes that introduce XSS risk when fed by
// user-controlled data. Severity reflects how dangerous direct use is.
var sinkPatterns = []struct {
	Rule     string
	Severity string
	Re       *regexp.Regexp
	Kind     string
	Detail   string
}{
	// Direct XSS sinks
	{"sink_eval", "high", regexp.MustCompile(`\beval\s*\(`), "sink", "eval() executes attacker-controlled strings as JS"},
	{"sink_new_function", "high", regexp.MustCompile(`\bnew\s+Function\s*\(`), "sink", "Function constructor — equivalent to eval"},
	{"sink_settimeout_string", "medium", regexp.MustCompile(`\bset(?:Timeout|Interval)\s*\(\s*['"][^'"]+['"]`), "sink", "String form of setTimeout/setInterval — eval-like"},
	{"sink_innerhtml", "high", regexp.MustCompile(`\.innerHTML\s*=`), "sink", "innerHTML assignment — HTML parse / XSS"},
	{"sink_outerhtml", "high", regexp.MustCompile(`\.outerHTML\s*=`), "sink", "outerHTML assignment — HTML parse / XSS"},
	{"sink_document_write", "high", regexp.MustCompile(`document\.write(?:ln)?\s*\(`), "sink", "document.write — HTML parse / XSS"},
	{"sink_insertadjacenthtml", "high", regexp.MustCompile(`\.insertAdjacentHTML\s*\(`), "sink", "insertAdjacentHTML — HTML parse / XSS"},
	{"sink_jquery_html", "medium", regexp.MustCompile(`\.html\s*\(\s*[^'"]`), "sink", "jQuery .html() with variable — XSS if unfiltered"},
	{"sink_jquery_append", "medium", regexp.MustCompile(`\.(?:append|prepend|after|before)\s*\(\s*[^'"]`), "sink", "jQuery DOM insertion with variable"},
	{"sink_react_dangerous", "high", regexp.MustCompile(`dangerouslySetInnerHTML`), "sink", "React dangerouslySetInnerHTML"},
	{"sink_vue_vhtml", "high", regexp.MustCompile(`v-html\s*=`), "sink", "Vue v-html directive"},
	{"sink_angular_bypass", "high", regexp.MustCompile(`bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)`), "sink", "Angular security bypass"},
	{"sink_srcdoc", "high", regexp.MustCompile(`\.srcdoc\s*=`), "sink", "iframe srcdoc — HTML injection"},
	{"sink_setattribute_on", "medium", regexp.MustCompile(`setAttribute\s*\(\s*['"]on\w+`), "sink", "setAttribute of inline event handler"},
	{"sink_javascript_uri", "medium", regexp.MustCompile(`(?:href|src|action)\s*=\s*['"]javascript:`), "sink", "javascript: URI"},
	{"sink_dom_href", "medium", regexp.MustCompile(`\.(?:href|src)\s*=\s*(?!['"])`), "sink", "href/src assignment with variable — javascript: URL risk"},

	// Sources — user-controlled data entering JS
	{"source_location_hash", "info", regexp.MustCompile(`location\.hash`), "source", "URL hash — user-controlled"},
	{"source_location_search", "info", regexp.MustCompile(`location\.search`), "source", "URL query — user-controlled"},
	{"source_location_href", "info", regexp.MustCompile(`location\.href`), "source", "URL — user-controlled"},
	{"source_document_referrer", "info", regexp.MustCompile(`document\.referrer`), "source", "Referrer header — user-controlled"},
	{"source_document_cookie", "info", regexp.MustCompile(`document\.cookie`), "source", "Cookie — potentially user-controlled"},
	{"source_window_name", "info", regexp.MustCompile(`window\.name`), "source", "window.name — persists across navigations, attacker-controlled"},
	{"source_postmessage_data", "info", regexp.MustCompile(`\bevent\.data\b|\be\.data\b`), "source", "postMessage data — user-controlled"},
	{"source_localstorage", "info", regexp.MustCompile(`localStorage\.(?:getItem|\[)`), "source", "localStorage — potentially attacker-writable via XSS"},
	{"source_sessionstorage", "info", regexp.MustCompile(`sessionStorage\.(?:getItem|\[)`), "source", "sessionStorage — potentially attacker-writable via XSS"},

	// Dangerous APIs
	{"danger_websocket_url", "info", regexp.MustCompile(`new\s+WebSocket\s*\(\s*[^'"]`), "sink", "WebSocket URL from variable"},
	{"danger_postmessage_star", "high", regexp.MustCompile(`\.postMessage\s*\([^,]+,\s*['"]\*['"]`), "sink", "postMessage with '*' targetOrigin — data leak"},
	{"danger_window_open", "info", regexp.MustCompile(`window\.open\s*\(\s*[^'"]`), "sink", "window.open with variable URL — open redirect / tabnabbing"},
}

// detectSinks fetches inline script text and scans for sink/source patterns.
func (s *Scanner) detectSinks(ctx context.Context, pageURL string) ([]SinkFinding, error) {
	var scriptsJSON string
	script := `JSON.stringify(
		Array.from(document.querySelectorAll('script:not([src])'))
			.map(s => s.textContent)
			.filter(t => t && t.length > 0)
	)`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &scriptsJSON)); err != nil {
		return nil, err
	}
	var scripts []string
	_ = json.Unmarshal([]byte(scriptsJSON), &scripts)

	var out []SinkFinding
	seen := map[string]bool{}
	for _, src := range scripts {
		for _, p := range sinkPatterns {
			matches := p.Re.FindAllStringIndex(src, 5) // cap 5 per rule
			for _, m := range matches {
				// Extract snippet (60 chars around match).
				start := m[0] - 30
				if start < 0 {
					start = 0
				}
				end := m[1] + 30
				if end > len(src) {
					end = len(src)
				}
				snippet := strings.TrimSpace(src[start:end])
				// Dedup by rule + snippet.
				key := p.Rule + "|" + snippet
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, SinkFinding{
					Rule: p.Rule, Severity: p.Severity, URL: pageURL,
					Snippet: snippet, Detail: p.Detail, Kind: p.Kind,
				})
			}
		}
	}
	return out, nil
}

// =============================================================================
// NEW: postMessage audit
// =============================================================================

func (s *Scanner) auditPostMessage(ctx context.Context, pageURL string) ([]PostMessageFinding, error) {
	var pmJSON string
	script := `JSON.stringify(window.__scannerweb_pm_listeners || [])`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &pmJSON)); err != nil {
		return nil, err
	}
	var listeners []struct {
		Source string `json:"source"`
		Stack  string `json:"stack"`
	}
	_ = json.Unmarshal([]byte(pmJSON), &listeners)

	var out []PostMessageFinding
	for _, l := range listeners {
		src := l.Source
		lower := strings.ToLower(src)

		// Check for missing origin validation.
		hasOriginCheck := strings.Contains(lower, "event.origin") || strings.Contains(lower, "e.origin")
		hasOriginCompare := regexp.MustCompile(`(?:event|e)\.origin\s*(?:===|!==|==|!=|=~)`).MatchString(src)
		hasOriginAllowlist := strings.Contains(lower, "allowedorigins") || strings.Contains(lower, "trustedorigins")
		hasDataValidation := regexp.MustCompile(`(?:event|e)\.data\s*(?:===|!==|==|!=)`).MatchString(src) ||
			strings.Contains(lower, "validate") || strings.Contains(lower, "schema")

		if !hasOriginCheck && !hasOriginCompare && !hasOriginAllowlist {
			out = append(out, PostMessageFinding{
				Rule: "postmessage_no_origin_check", Severity: "high", URL: pageURL,
				Detail: "message listener does not validate event.origin — any origin can post",
				Snippet: truncate(src, 200),
			})
		} else if !hasOriginAllowlist && hasOriginCompare {
			out = append(out, PostMessageFinding{
				Rule: "postmessage_origin_compare_unsafe", Severity: "medium", URL: pageURL,
				Detail: "message listener compares origin without an allowlist — verify logic (substring bypass?)",
				Snippet: truncate(src, 200),
			})
		}
		if !hasDataValidation {
			out = append(out, PostMessageFinding{
				Rule: "postmessage_no_data_validation", Severity: "low", URL: pageURL,
				Detail: "message listener does not validate event.data structure",
				Snippet: truncate(src, 200),
			})
		}
		// Dangerous sinks inside the listener.
		if regexp.MustCompile(`\b(?:eval|innerHTML|document\.write|dangerouslySetInnerHTML)\b`).MatchString(src) {
			out = append(out, PostMessageFinding{
				Rule: "postmessage_with_dangerous_sink", Severity: "critical", URL: pageURL,
				Detail: "message listener feeds data into a dangerous sink (eval/innerHTML/document.write)",
				Snippet: truncate(src, 200),
			})
		}
	}

	// Also check outbound .postMessage with '*' targetOrigin in inline scripts.
	var scriptsJSON string
	script2 := `JSON.stringify(Array.from(document.querySelectorAll('script:not([src])')).map(s=>s.textContent).filter(Boolean))`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script2, &scriptsJSON)); err == nil {
		var scripts []string
		_ = json.Unmarshal([]byte(scriptsJSON), &scripts)
		outboundRe := regexp.MustCompile(`\.postMessage\s*\([^,]+,\s*['"]\*['"]`)
		for _, src := range scripts {
			for _, m := range outboundRe.FindAllStringIndex(src, 3) {
				start := m[0] - 30
				if start < 0 {
					start = 0
				}
				end := m[1] + 30
				if end > len(src) {
					end = len(src)
				}
				out = append(out, PostMessageFinding{
					Rule: "postmessage_outbound_star", Severity: "high", URL: pageURL,
					Detail: "postMessage with '*' targetOrigin — any embedding page can read message",
					Snippet: strings.TrimSpace(src[start:end]),
				})
			}
		}
	}
	return out, nil
}

// =============================================================================
// NEW: WebSocket detection
// =============================================================================

func (s *Scanner) detectWebSockets(ctx context.Context, pageURL string) ([]WebSocketFinding, error) {
	var wsJSON string
	script := `JSON.stringify(window.__scannerweb_ws || [])`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &wsJSON)); err != nil {
		return nil, err
	}
	var insts []struct {
		URL       string `json:"url"`
		Protocols interface{} `json:"protocols"`
		Stack     string `json:"stack"`
	}
	_ = json.Unmarshal([]byte(wsJSON), &insts)

	var out []WebSocketFinding
	for _, inst := range insts {
		f := analyzeWebSocketRequest(inst.URL, pageURL)
		out = append(out, f)
	}
	return out, nil
}

// analyzeWebSocketRequest returns findings for one WebSocket URL.
func analyzeWebSocketRequest(wsURL, documentURL string) WebSocketFinding {
	f := WebSocketFinding{WSURL: wsURL, URL: documentURL}

	lower := strings.ToLower(wsURL)
	if strings.HasPrefix(lower, "ws://") && strings.HasPrefix(strings.ToLower(documentURL), "https://") {
		f.Rule = "websocket_insecure_ws"
		f.Severity = "high"
		f.Detail = "ws:// from HTTPS page — MITM can inject messages"
		return f
	}
	// Token in URL.
	if regexp.MustCompile(`(?i)(?:token|key|auth|session|sid)=`).MatchString(wsURL) {
		f.Rule = "websocket_token_in_url"
		f.Severity = "medium"
		f.Detail = "WebSocket URL contains a token — leaks in Referer / logs / proxies"
		return f
	}
	// Third-party WS.
	if u, err := url.Parse(wsURL); err == nil && u.Host != "" {
		if du, err2 := url.Parse(documentURL); err2 == nil && u.Host != du.Host {
			f.Rule = "websocket_thirdparty"
			f.Severity = "low"
			f.Detail = fmt.Sprintf("WebSocket to third party: %s", u.Host)
			return f
		}
	}
	f.Rule = "websocket_detected"
	f.Severity = "info"
	f.Detail = "WebSocket connection"
	return f
}

// =============================================================================
// NEW: CSP violation capture
// =============================================================================

func (s *Scanner) collectCSPViolations(ctx context.Context, pageURL string) ([]CSPViolation, error) {
	var cspJSON string
	script := `JSON.stringify(window.__scannerweb_csp || [])`
	if err := chromedp.Run(ctx, chromedp.Evaluate(script, &cspJSON)); err != nil {
		return nil, err
	}
	var raw []struct {
		BlockedURI        string `json:"blockedURI"`
		ViolatedDirective string `json:"violatedDirective"`
		EffectiveDirective string `json:"effectiveDirective"`
		OriginalPolicy    string `json:"originalPolicy"`
		Disposition       string `json:"disposition"`
		SourceFile        string `json:"sourceFile"`
		LineNumber        int    `json:"lineNumber"`
		DocumentURI       string `json:"documentURI"`
	}
	_ = json.Unmarshal([]byte(cspJSON), &raw)

	var out []CSPViolation
	for _, v := range raw {
		out = append(out, CSPViolation{
			URL:                pageURL,
			BlockedURI:         v.BlockedURI,
			ViolatedDirective:  v.ViolatedDirective,
			EffectiveDirective: v.EffectiveDirective,
			OriginalPolicy:     v.OriginalPolicy,
			Disposition:        v.Disposition,
			SourceFile:         v.SourceFile,
			Line:               v.LineNumber,
		})
	}
	return out, nil
}

// collectBootstrapFindings flushes CSP/WS/errors from the last page.
func (s *Scanner) collectBootstrapFindings(ctx context.Context, pageURL string, mu *sync.Mutex,
	cspViols *[]CSPViolation, wsFinds *[]WebSocketFinding, console *[]ConsoleMessage,
	pmFinds *[]PostMessageFinding, reflectFinds *[]ReflectionFinding) {
	if pageURL == "" {
		return
	}
	if v, err := s.collectCSPViolations(ctx, pageURL); err == nil && len(v) > 0 {
		mu.Lock()
		*cspViols = append(*cspViols, v...)
		mu.Unlock()
	}
	if ws, err := s.detectWebSockets(ctx, pageURL); err == nil && len(ws) > 0 {
		mu.Lock()
		*wsFinds = append(*wsFinds, ws...)
		mu.Unlock()
	}
	if pm, err := s.auditPostMessage(ctx, pageURL); err == nil && len(pm) > 0 {
		mu.Lock()
		*pmFinds = append(*pmFinds, pm...)
		mu.Unlock()
	}
	// Page errors captured by the injected error handler.
	var errJSON string
	if err := chromedp.Run(ctx, chromedp.Evaluate(`JSON.stringify(window.__scannerweb_errors || [])`, &errJSON)); err == nil {
		var errs []struct {
			Msg  string `json:"msg"`
			Src  string `json:"src"`
			Line int    `json:"line"`
		}
		_ = json.Unmarshal([]byte(errJSON), &errs)
		mu.Lock()
		for _, e := range errs {
			*console = append(*console, ConsoleMessage{
				Type: "pageerror", Text: e.Msg, URL: e.Src, Line: e.Line,
			})
		}
		mu.Unlock()
	}
}

// =============================================================================
// Storage
// =============================================================================

func (s *Scanner) dumpStorage(ctx context.Context) (map[string]string, map[string]string, error) {
	var ls, ss map[string]string

	if err := chromedp.Run(ctx, chromedp.Evaluate(
		`JSON.stringify(Object.fromEntries(Object.entries(localStorage)))`, &ls)); err != nil {
		// ignore
	}
	if err := chromedp.Run(ctx, chromedp.Evaluate(
		`JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))`, &ss)); err != nil {
		// ignore
	}
	return ls, ss, nil
}

// =============================================================================
// Reflection
// =============================================================================

// probeReflection navigates to a form-submitted URL and checks whether the
// injected marker appears in HTML / JS context.
func (s *Scanner) probeReflection(ctx context.Context, formURL, marker string) *ReflectionFinding {
	pctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	var html string
	if err := chromedp.Run(pctx,
		chromedp.Navigate(formURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.OuterHTML("html", &html, chromedp.ByQuery),
	); err != nil {
		return nil
	}

	idx := strings.Index(html, marker)
	if idx < 0 {
		return nil
	}

	// Determine context.
	before := html[max(0, idx-100):idx]
	context := "html"

	if regexp.MustCompile(`(?i)<script[^>]*>[^<]*$`).MatchString(before) {
		context = "script"
	} else if regexp.MustCompile(`(?i)="[^"]*$`).MatchString(before) {
		context = "attr"
	} else if strings.Contains(before, "href=") || strings.Contains(before, "src=") {
		context = "url"
	}

	severity := "medium"
	detail := "Parameter reflected in HTML"
	switch context {
	case "script":
		severity = "critical"
		detail = "Parameter reflected inside <script> — direct JS injection"
	case "attr":
		severity = "high"
		detail = "Parameter reflected inside HTML attribute — attribute injection / XSS"
	case "url":
		severity = "high"
		detail = "Parameter reflected inside href/src — javascript: URL possible"
	}

	// Extract param name from URL.
	param := ""
	if u, err := url.Parse(formURL); err == nil {
		for k, vs := range u.Query() {
			for _, v := range vs {
				if v == marker {
					param = k
					break
				}
			}
		}
	}

	snippet := ""
	if idx+len(marker)+50 < len(html) {
		snippet = html[max(0, idx-50):idx+len(marker)+50]
	} else {
		snippet = html[max(0, idx-50):]
	}

	return &ReflectionFinding{
		URL: formURL, Param: param, Context: context,
		Snippet: strings.TrimSpace(snippet), Severity: severity,
	}
}

// =============================================================================
// Helpers
// =============================================================================

func buildFormURL(base string, f FormInfo, marker string) string {
	if len(f.Fields) == 0 {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := u.Query()
	for _, field := range f.Fields {
		switch strings.ToLower(field.Type) {
		case "submit", "button", "reset", "image", "file":
			continue
		case "checkbox", "radio":
			if field.Value != "" {
				q.Set(field.Name, field.Value)
			}
		case "hidden":
			q.Set(field.Name, field.Value)
		default:
			q.Set(field.Name, marker)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// =============================================================================
// Report formatting
// =============================================================================

func (r *Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== Scan Report ===\n")
	fmt.Fprintf(&b, "Target:    %s\n", r.Target)
	fmt.Fprintf(&b, "Final URL: %s\n", r.FinalURL)
	fmt.Fprintf(&b, "Title:     %s\n", r.Title)
	fmt.Fprintf(&b, "Status:    %d\n", r.Status)
	fmt.Fprintf(&b, "Took:      %s\n", r.Took.Round(time.Millisecond))
	fmt.Fprintf(&b, "Pages:     %d\n", len(r.Pages))
	fmt.Fprintf(&b, "Requests:  %d\n", r.Network.TotalRequests)
	fmt.Fprintf(&b, "Hosts:     %d (%d third-party)\n", len(r.Network.UniqueHosts), len(r.Network.ThirdParties))

	if len(r.Sinks) > 0 {
		fmt.Fprintf(&b, "\n--- Sinks / Sources (%d) ---\n", len(r.Sinks))
		for _, s := range r.Sinks {
			fmt.Fprintf(&b, "[%s/%s] %s\n  %s\n  %s\n", s.Severity, s.Kind, s.Rule, s.Detail, s.Snippet)
		}
	}
	if len(r.PostMessage) > 0 {
		fmt.Fprintf(&b, "\n--- PostMessage Findings (%d) ---\n", len(r.PostMessage))
		for _, p := range r.PostMessage {
			fmt.Fprintf(&b, "[%s] %s\n  %s\n", p.Severity, p.Rule, p.Detail)
		}
	}
	if len(r.WebSockets) > 0 {
		fmt.Fprintf(&b, "\n--- WebSockets (%d) ---\n", len(r.WebSockets))
		for _, w := range r.WebSockets {
			fmt.Fprintf(&b, "[%s] %s -> %s\n  %s\n", w.Severity, w.Rule, w.WSURL, w.Detail)
		}
	}
	if len(r.CSPViolations) > 0 {
		fmt.Fprintf(&b, "\n--- CSP Violations (%d) ---\n", len(r.CSPViolations))
		for _, v := range r.CSPViolations {
			fmt.Fprintf(&b, "  blocked=%s directive=%s file=%s:%d\n",
				v.BlockedURI, v.EffectiveDirective, v.SourceFile, v.Line)
		}
	}
	if len(r.Reflections) > 0 {
		fmt.Fprintf(&b, "\n--- Reflections (%d) ---\n", len(r.Reflections))
		for _, rf := range r.Reflections {
			fmt.Fprintf(&b, "[%s] param=%q context=%s\n  %s\n", rf.Severity, rf.Param, rf.Context, rf.Snippet)
		}
	}
	if len(r.Cookies) > 0 {
		fmt.Fprintf(&b, "\n--- Cookies (%d) ---\n", len(r.Cookies))
		for _, c := range r.Cookies {
			fmt.Fprintf(&b, "  [%s] %s domain=%s httponly=%v secure=%v samesite=%s\n",
				c.Source, c.Name, c.Domain, c.HTTPOnly, c.Secure, c.SameSite)
			for _, i := range c.Issues {
				fmt.Fprintf(&b, "    ⚠ %s\n", i)
			}
		}
	}
	if len(r.JSFindings) > 0 {
		fmt.Fprintf(&b, "\n--- JS Findings (%d) ---\n", len(r.JSFindings))
		for _, f := range r.JSFindings {
			fmt.Fprintf(&b, "[%s] %s @ %s\n  %s\n", f.Severity, f.Rule, f.URL, f.Detail)
		}
	}
	if len(r.DOMIssues) > 0 {
		fmt.Fprintf(&b, "\n--- DOM Issues (%d) ---\n", len(r.DOMIssues))
		for _, d := range r.DOMIssues {
			fmt.Fprintf(&b, "[%s] %s\n  %s\n", d.Severity, d.Rule, d.Detail)
		}
	}
	if len(r.MixedContent) > 0 {
		fmt.Fprintf(&b, "\n--- Mixed Content (%d) ---\n", len(r.MixedContent))
		for _, u := range r.MixedContent {
			fmt.Fprintf(&b, "  %s\n", u)
		}
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "\n--- Errors (%d) ---\n", len(r.Errors))
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  %s\n", e)
		}
	}
	return b.String()
}

func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// =============================================================================
// Correlator
// =============================================================================

func (r *Report) Correlate(topCMS, topWAF string, wafBlocked bool) []string {
	var notes []string
	if topCMS != "" {
		notes = append(notes, fmt.Sprintf("CMS detected: %s — check version-specific CVEs", topCMS))
	}
	if topWAF != "" {
		if wafBlocked {
			notes = append(notes, fmt.Sprintf("WAF %s actively blocking — expect 403s during form submission", topWAF))
		} else {
			notes = append(notes, fmt.Sprintf("WAF/CDN detected: %s (passive)", topWAF))
		}
	}
	// Cross-correlate sinks + reflections.
	sinkReflectionHit := false
	for _, rf := range r.Reflections {
		if rf.Context == "script" || rf.Context == "attr" {
			sinkReflectionHit = true
			notes = append(notes, fmt.Sprintf("⚠ Reflection in %s context at %s — likely XSS, verify manually", rf.Context, rf.URL))
		}
	}
	if sinkReflectionHit {
		for _, sk := range r.Sinks {
			if sk.Kind == "sink" && (sk.Rule == "sink_innerhtml" || sk.Rule == "sink_eval") {
				notes = append(notes, "⚠ Reflection + "+sk.Rule+" — high-confidence XSS chain")
			}
		}
	}
	// PM + dangerous sink.
	for _, pm := range r.PostMessage {
		if pm.Rule == "postmessage_with_dangerous_sink" {
			notes = append(notes, "⚠ postMessage listener feeds data to eval/innerHTML — DOM XSS via cross-origin message")
		}
	}
	// WS + insecure.
	for _, w := range r.WebSockets {
		if w.Rule == "websocket_insecure_ws" {
			notes = append(notes, "⚠ Insecure WebSocket on HTTPS page — MITM injection possible")
		}
	}
	// Cookies.
	for _, c := range r.Cookies {
		if strings.Contains(strings.Join(c.Issues, " "), "session-like") {
			notes = append(notes, fmt.Sprintf("⚠ Session-like cookie without HttpOnly: %s", c.Name))
		}
	}
	return notes
}
