package thttp

import (
	"net/http"
	"runtime/debug"

	"go.uber.org/zap"

	"github.com/outofforest/logger"
)

// Recover is a middleware that catches and logs panics from HTTP handlers.
func Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:contextcheck
		defer func() {
			if p := recover(); p != nil {
				w.WriteHeader(http.StatusInternalServerError)
				logger.Get(r.Context()).Error("Panic in HTTP handler", zap.Any("error", p), zap.ByteString("stack", debug.Stack()))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
