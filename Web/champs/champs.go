package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"
)

const staticDir = "./static"

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/photos/", photoHandler)

	fmt.Println("server running at http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	var tmplFile = "index.tmpl"
	t := template.Must(template.New(tmplFile).ParseFiles(tmplFile))
	t.Execute(w, nil)
}

func photoHandler(w http.ResponseWriter, r *http.Request) {
	slog.Info("photo req", "path", r.URL.Path)
	path := strings.TrimPrefix(r.URL.Path, "/photos/")
	if path == "" || strings.Contains(path, "..") {
		http.Error(w, "invalid photo path", 400)
		return
	}
	path, _ = url.PathUnescape(path)
	absPath := filepath.Join(staticDir, path)
	http.ServeFile(w, r, absPath)
}
