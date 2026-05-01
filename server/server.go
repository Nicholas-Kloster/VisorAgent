package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Hit struct {
	Path  string
	Query url.Values
	Time  time.Time
}

type Server struct {
	mu       sync.Mutex
	hits     []Hit
	payloads sync.Map // path -> content string
	srv      *http.Server
	BaseURL  string
}

func New() (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	s := &Server{BaseURL: fmt.Sprintf("http://127.0.0.1:%d", port)}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)

	s.srv = &http.Server{Handler: mux}
	go s.srv.Serve(ln)
	return s, nil
}

func (s *Server) SetPayload(path, content string) {
	s.payloads.Store(path, content)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if val, ok := s.payloads.Load(r.URL.Path); ok {
		content := val.(string)
		ct := "text/plain"
		if strings.HasSuffix(r.URL.Path, ".html") {
			ct = "text/html"
		}
		w.Header().Set("Content-Type", ct)
		fmt.Fprint(w, content)
		return
	}

	// Listener — record the hit
	s.mu.Lock()
	s.hits = append(s.hits, Hit{
		Path:  r.URL.Path,
		Query: r.URL.Query(),
		Time:  time.Now(),
	})
	s.mu.Unlock()

	w.WriteHeader(200)
	fmt.Fprint(w, "OK")
}

func (s *Server) Hits() []Hit {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Hit, len(s.hits))
	copy(out, s.hits)
	return out
}

func (s *Server) HitsMatching(substr string) []Hit {
	var out []Hit
	for _, h := range s.Hits() {
		if strings.Contains(h.Path, substr) || strings.Contains(h.Query.Encode(), substr) {
			out = append(out, h)
		}
	}
	return out
}

func (s *Server) Reset() {
	s.mu.Lock()
	s.hits = nil
	s.mu.Unlock()
}

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.srv.Shutdown(ctx)
}
