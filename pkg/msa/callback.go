package msa

import (
	"net/http"
)

type CallbackServer struct {
	codeChannel chan string
	server      *http.Server
}

func NewCallbackServer(codeChannel chan string) *CallbackServer {
	return &CallbackServer{
		codeChannel: codeChannel,
	}
}

func (cs *CallbackServer) Start() error {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		cs.codeChannel <- code

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Blockbot authorized. You may close this window."))
	})
	cs.server = &http.Server{
		Addr:    ":8080",
		Handler: http.DefaultServeMux,
	}
	return cs.server.ListenAndServe()
}

func (cs *CallbackServer) Stop() error {
	return cs.server.Shutdown(nil)
}
