package main

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	"github.com/oscartbeaumont/windows_mdm/mdm/windows/wstep"
)

// Handy Tools/Links:
//	https://www.onlinetool.io/xmltogo/
//  https://www.freeformatter.com/xml-formatter.html
//  https://medium.com/@xoen/golang-read-from-an-io-readwriter-without-loosing-its-content-2c6911805361

// TODO:
//  - Verify Spec Against The PolicyService and EnrollmentService
//  - Allow device to renew certificates
//	- Do MDM Clients Send HTTP Headers that I should know?
//  - Cleanup TODO's In Code
//	- Make sure the encoding is set correctly to spec for all the requests -> Maybe abtrast the response
//	- Stop using w.Write if not error handled
//  - Sanitise user input before putting back into xml response
//  - Check against MDM docs on security

// config stores the configuration for the server
var config = struct {
	HTTPSCertPath string
	HTTPSKeyPath  string
	Domain        string
	ProfileName   string
	Subject       pkix.Name // The Identity CA Subject
}{
	Domain:        "mdm.otbeaumont.me",
	HTTPSCertPath: "./certs/https.cert",
	HTTPSKeyPath:  "./certs/https.key",
	ProfileName:   "Oscar's Demo",
	Subject: pkix.Name{ // TODO: Test Changing
		Country:            []string{"US"}, // TEMP: Make Compatible With The SCEP Payload
		Organization:       []string{"groob-io"},
		OrganizationalUnit: []string{"SCEP CA"}, // TODO: Load From Configuration
	},
}

// This is run when the program starts
func main() {
	// Print to the screen the startup message
	log.Println("Starting Windows MDM Demo. Created By Oscar Beaumont!")
	log.Println("WARNING: DO NOT PUT THIS INTO PRODUCTION OR THINK THIS CORRECTLY FOLLOWS THE MICROSOFT DOCUMENTATION.")
	log.Println("This demo was created out of fraustation of the documentation and protocol and so is what I understood from the documentation and months of research.")
	fmt.Println()

	// Create a url router
	r := mux.NewRouter()

	// Create WSTEP Cert Store
	wstep := wstep.Service{}
	if err := wstep.Init(config.Subject); err != nil {
		panic(err) // TODO: Error Handling
	}

	// Mount url routes. The file is containing the routes handler is put in a comment.
	// User Side - These routes are for use by the end user
	r.Path("/").Methods("GET").HandlerFunc(IndexHandler)        // main.go
	r.Path("/enroll").Methods("GET").HandlerFunc(EnrollHandler) // main.go
	// MDM Side - These routes are all for the MDM protocol
	r.Path("/EnrollmentServer/Discovery.svc").Methods("GET", "POST").HandlerFunc(DiscoveryHandler(config.Domain))                                     // mdm-discovery.go
	r.Path("/EnrollmentServer/PolicyService.svc").Methods("POST").HandlerFunc(PolicyServiceHandler())                                                 // mdm-policyservice.go
	r.Path("/EnrollmentServer/EnrollmentService.svc").Methods("POST").HandlerFunc(EnrollmentServiceHandler(config.Domain, wstep, config.ProfileName)) // mdm-enrollmentservice.go
	// r.Path("/EnrollmentServer/DeviceEnrollment.svc").Methods("POST").HandlerFunc(DeviceEnrollmentHandler()) // mdm-discovery.go

	// Print to screen and start listening over https using the router defined above
	log.Println("Listening at :9000 and at domain " + config.Domain)
	log.Fatal(http.ListenAndServeTLS(":9000", config.HTTPSCertPath, config.HTTPSKeyPath, handlers.LoggingHandler(os.Stdout, global(r))))
}

// global is a basic HTTP middleware. It set some HTTP headers on all of the requests.
func global(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Custom HTTP Headers
		w.Header().Set("Server", "Windows-MDM-Demo")
		w.Header().Set("X-Creator", "Oscar Beaumont")

		// Continue With The Normal HTTP Handler
		h.ServeHTTP(w, r)
	})
}

// IndexHandler is the http handler for the root page. This is just a basic message for testing if the server is online.
func IndexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	fmt.Fprintf(w, `<span>Demo Windows MDM Server. Created By <a target="_black" href="https://otbeaumont.me">Oscar Beaumont.</a></span>`)
}

// EnrollHandler will initiate the enrollment process from a web broswer on a Windows machine.
func EnrollHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "ms-device-enrollment:?mode=mdm&username=example@"+config.Domain, 301) // FUTURE: Mess around with with &accesstoken=boop
}
