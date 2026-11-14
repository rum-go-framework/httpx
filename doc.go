// Package httpx collects small, stdlib-only HTTP helpers and middleware.
//
// Every middleware is a plain func(http.Handler) http.Handler (or a
// constructor returning one), so it composes with net/http and chi alike.
// Nothing here mounts routes or owns control flow beyond short-circuiting
// the request it was built to guard.
//
// Anything chi/v5/middleware already provides (RequestID, RealIP, Recoverer,
// Timeout, StripSlashes, RedirectSlashes, NoCache, Compress, Throttle...) is
// deliberately absent: use chi's.
package httpx
