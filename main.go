package main

import (
	"io/ioutil"
	"log"
	"net/http"

	"github.com/matryer/way"
	_ "github.com/motemen/go-loghttp/global"
)

// The Function Run When The Server Starts
func main() {
	log.Println("Started Windows MDM Demo On Port 8000")
	router := way.NewRouter()

	// The HTTP Routes
	router.HandleFunc("GET", "/", indexHandler)                                                       // main.go
	router.HandleFunc("GET", "/EnrollmentServer/Discovery.svc", discoveryGETHandler)                  // discovery.go
	router.HandleFunc("POST", "/EnrollmentServer/Discovery.svc", discoveryPOSTHandler)                // discovery.go
	router.HandleFunc("POST", "/EnrollmentServer/PolicyService.svc", enrollmentPolicyHandler)         // enrollment.go
	router.HandleFunc("POST", "/EnrollmentServer/EnrollmentService.svc", enrollmentWebServiceHandler) // enrollment.go
	//router.HandleFunc("POST", "/EnrollmentServer/DeviceEnrollment.svc", ) // enrollment.go

	router.NotFound = http.HandlerFunc(notFoundHandler) // main.go

	// Start The HTTP Server Listening
	log.Fatalln(http.ListenAndServe(":8000", logRequest(router)))
}

// The Response To Access The Index Page (Just A Placeholder)
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Demo Windows MDM Server!"))
}

// The Response To Known Web Routes
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body) // Get The Body From The Request
	log.Println(string(body))         // Print The Body To The Console

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Not Found: 404"))
}

// The HTTP Request Logger
func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})
}
