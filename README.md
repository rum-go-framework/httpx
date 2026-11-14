# httpx

Small, stdlib-only HTTP helpers and middleware. Every middleware is a plain
`func(http.Handler) http.Handler`; nothing mounts routes. Go 1.25, zero
dependencies.

| API | What |
|---|---|
| `Health(probes...)` | liveness/readiness/startup probes with pluggable `func(ctx) error` checks |
| `NewRateLimiter(n, window).Middleware(keyFn)` | in-memory per-key limiter, 429 + `Retry-After`, bounded memory |
| `SecurityHeaders(cfg)` | nosniff, frame options, referrer policy, optional CSP/HSTS |
| `RequestLogger(*slog.Logger)` | one structured access-log line per request |
| `DecodeJSONBody` / `DecodeJSONBodyLimit` | strict JSON decode (1 MiB default cap), errors are `*MalformedRequest` |
| `JSONResponse` | `Response` envelope writer |

Not here on purpose, use chi's: `RequestID`, `RealIP`, `Recoverer`, `Timeout`,
`StripSlashes`/`RedirectSlashes`, `NoCache`, `Compress`, `Heartbeat`,
`Throttle`. CSRF: use `http.CrossOriginProtection`.

## Wiring with chi

```go
login := httpx.NewRateLimiter(5, time.Minute)

r := chi.NewRouter()
r.Use(middleware.RealIP) // before anything that reads the client IP
r.Use(middleware.RequestID)
r.Use(httpx.Health(
    httpx.Probe{Path: httpx.LivenessPath},
    httpx.Probe{Path: httpx.ReadinessPath, Check: db.PingContext},
))
r.Use(httpx.RequestLogger(slog.Default()))
r.Use(middleware.Recoverer)
r.Use(middleware.Timeout(30 * time.Second))
r.Use(httpx.SecurityHeaders(httpx.SecurityHeadersConfig{HSTSMaxAge: 365 * 24 * time.Hour}))

r.With(login.Middleware(nil)).Post("/login", loginHandler)

func createUser(w http.ResponseWriter, r *http.Request) {
    var in CreateUser
    if err := httpx.DecodeJSONBody(w, r, &in); err != nil {
        var mr *httpx.MalformedRequest
        if errors.As(err, &mr) {
            httpx.JSONResponse(w, mr.Msg, nil, mr.Status)
            return
        }
        httpx.JSONResponse(w, "internal error", nil, http.StatusInternalServerError)
        return
    }
    httpx.JSONResponse(w, "created", in, http.StatusCreated)
}
```

## Notes

- The rate limiter is per process (fixed window). Keys are capped at 10 000;
  idle keys are swept lazily, no goroutine to stop. `ClientIP` ignores
  forwarding headers, so install `RealIP` first when behind a proxy.
- `Health` hides check errors from the response; log them in the check.
