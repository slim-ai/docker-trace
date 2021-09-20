package main

import (
	"log"
	"net/http"
	"strings"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	token := strings.Split(r.URL.Path, "/hello/")[1]
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(token))
}

func main() {
	http.HandleFunc("/", Handler)
	err := http.ListenAndServeTLS(":8080", "ssl.crt", "ssl.key", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
