package api

import (
	"log"
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements per-key rate limiting to prevent abuse
type RateLimiter struct {
	requests map[string][]time.Time
	mutex    sync.RWMutex
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter with specified limit and time window
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}

	// Cleanup old entries every minute
	go rl.cleanup()

	return rl
}

// cleanup removes expired rate limit entries periodically
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mutex.Lock()
		now := time.Now()
		for key, times := range rl.requests {
			// Remove entries older than window
			var valid []time.Time
			for _, t := range times {
				if now.Sub(t) < rl.window {
					valid = append(valid, t)
				}
			}
			if len(valid) > 0 {
				rl.requests[key] = valid
			} else {
				delete(rl.requests, key)
			}
		}
		rl.mutex.Unlock()
	}
}

// Allow checks if a request should be allowed for the given key
func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	times := rl.requests[key]

	// Remove old requests
	var valid []time.Time
	for _, t := range times {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.limit {
		return false
	}

	valid = append(valid, now)
	rl.requests[key] = valid
	return true
}

// RateLimitMiddleware wraps an HTTP handler with rate limiting
func RateLimitMiddleware(limiter *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Use IP address as key (could also use API key if available)
		key := r.RemoteAddr

		if !limiter.Allow(key) {
			log.Printf("[SECURITY] Rate limit exceeded for %s on %s", key, r.URL.Path)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}

// AuditLog logs security-relevant events with masked API keys
func AuditLog(apiKey, action, resource, result string) {
	// Mask API key for logging (show only first 8 chars)
	maskedKey := "****"
	if len(apiKey) > 8 {
		maskedKey = apiKey[:8] + "****"
	}

	log.Printf("[AUDIT] Key=%s Action=%s Resource=%s Result=%s", maskedKey, action, resource, result)
}

// AuditMiddleware wraps an HTTP handler with audit logging
func AuditMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Get API key for audit trail
		apiKey := r.Header.Get("x-api-key")
		if apiKey == "" {
			if cookie, err := r.Cookie("x-api-key"); err == nil {
				apiKey = cookie.Value
			}
		}

		// Create response writer wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call next handler
		next(rw, r)

		// Log the request
		duration := time.Since(start)
		result := "SUCCESS"
		if rw.statusCode >= 400 {
			result = "FAILED"
		}

		AuditLog(apiKey, r.Method, r.URL.Path, result)
		log.Printf("[ACCESS] %s %s - Status: %d - Duration: %v", r.Method, r.URL.Path, rw.statusCode, duration)
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
