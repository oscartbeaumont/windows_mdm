package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

func main() {
	// Create The Router
	router := mux.NewRouter()
	r := router.Host("mdm.otbeaumont.me").Subrouter()

	//TODO: Minification Applied To The Returned Bodies -> Make Parser Generate It That Way To Save Preformance

	// "discovery.go" Endpoints
	r.PathPrefix("/").Methods("GET").HandlerFunc(IndexHandler)
	r.PathPrefix("/EnrollmentServer/Discovery.svc").Methods("GET").HandlerFunc(GetDiscoveryHandler)
	r.PathPrefix("/EnrollmentServer/Discovery.svc").Methods("POST").HandlerFunc(PostDiscoveryHandler)

	// "EnrollmentService.go" Endpoints
	r.PathPrefix("/EnrollmentPolicyService.svc").Methods("POST").HandlerFunc(EnrollmentPolicyServiceHandler)
	r.PathPrefix("/EnrollmentService.svc").Methods("POST").HandlerFunc(EnrollmentServiceHandler)

	// Start The Server Listening
	log.Println("Started Listening On `https://mdm.otbeaumont.me`")
	log.Fatal(http.ListenAndServeTLS(":443", "certs/bundle.crt", "certs/server.key", handlers.LoggingHandler(os.Stdout, router)))
}
