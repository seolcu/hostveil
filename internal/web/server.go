package web

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/seolcu/hostveil/internal/domain"
	"github.com/seolcu/hostveil/internal/export"
)

//go:embed template/*.html
var templateFS embed.FS

type Server struct {
	result *domain.ScanResult
	tmpl   *template.Template
	addr   string
}

func NewServer(result *domain.ScanResult, host string, port int) *Server {
	tmpl := template.Must(template.ParseFS(templateFS, "template/*.html"))
	return &Server{
		result: result,
		tmpl:   tmpl,
		addr:   fmt.Sprintf("%s:%d", host, port),
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", s.handleIndex)
	mux.HandleFunc("GET /overview", s.handleOverview)
	mux.HandleFunc("GET /findings", s.handleFindings)
	mux.HandleFunc("GET /history", s.handleHistory)
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("GET /api/overview", s.handleAPIOverview)
	mux.HandleFunc("GET /api/findings", s.handleAPIFindings)

	log.Printf("Web server starting on http://%s", s.addr)
	return http.ListenAndServe(s.addr, mux)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, "index.html", nil)
}

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	s.render(w, "overview.html", s.result)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Result   *domain.ScanResult
		Severity string
		Source   string
	}{
		Result:   s.result,
		Severity: r.URL.Query().Get("severity"),
		Source:   r.URL.Query().Get("source"),
	}
	s.render(w, "findings.html", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.render(w, "settings.html", nil)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.render(w, "history.html", s.result)
}

func (s *Server) handleAPIOverview(w http.ResponseWriter, r *http.Request) {
	json, err := export.JSON(s.result, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(json))
}

func (s *Server) handleAPIFindings(w http.ResponseWriter, r *http.Request) {
	json, err := export.JSON(s.result, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(json))
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
