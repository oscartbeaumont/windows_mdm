// This file contains the code that is run upon starting the application.
// It mounts the HTTP request handlers from the other files and begins a listening HTTPS server.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

// Global config, populated via Command line flags
var domain string
var deepLinkUserEmail string
var authPolicy string

// This is run upon executing the command
func main() {
	// Print to the screen the startup message
	log.Println("Starting Windows MDM Demo. Created By Oscar Beaumont!")
	log.Println("WARNING: DO NOT PUT THIS INTO PRODUCTION!")
	log.Println("This implementation is probably not perfectly to spec but neither is the behaviour I observed from Intune so...")
	log.Println("It is designed to ignore all protocol security measures and authentication for simplicity. Productions servers MUST ALWAYS use all security measures for a security critical protocol like this.")
	fmt.Println()

	// Parse CMD flags. This populates the varibles defined above
	flag.StringVar(&domain, "domain", "mdm.otbeaumont.me", "Your servers primary domain")
	flag.StringVar(&deepLinkUserEmail, "dl-user-email", "oscar@otbeaumont.me", "An email of the enrolling user when using the Deeplink ('/deeplink')")
	flag.StringVar(&authPolicy, "auth-policy", "Federated", "An email of the enrolling user when using the Deeplink ('/deeplink')")
	flag.Parse()

	// Verify authPolicy is valid
	if authPolicy != "Federated" && authPolicy != "OnPremise" {
		panic("unsupported authpolicy")
	}

	// Create HTTP request router
	r := mux.NewRouter()

	// Root path page.
	// This is NOT MDM related.
	r.Path("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(`<span>Demo Windows MDM Server. Created By <a target="_black" href="https://otbeaumont.me">Oscar Beaumont.</a></span>`))
	})

	r.Path("/deeplink").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "ms-device-enrollment:?mode=mdm&username="+deepLinkUserEmail, 301)
	})

	r.Path("/EnrollmentServer/Auth").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(`<h3>MDM Federated Login</h3>
<form method="post" action="` + r.URL.Query().Get("appru") + `">
	<p><input type="hidden" name="wresult" value="TODOSpecialTokenWhichVerifiesAuth" /></p>
	<input type="submit" value="Login" />
</form>`))

	})

	r.Path("/EnrollmentServer/ToS").Methods("GET").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(`<h3>AzureAD Term Of Service</h3>
<button onClick="acceptBtn()">Accept</button>
<script>
	function acceptBtn() {
		var urlParams = new URLSearchParams(window.location.search);

		if (!urlParams.has('redirect_uri')) {
			alert('Redirect url not found. Did you open this in your broswer?');
		} else {
			window.location = urlParams.get('redirect_uri') + "?IsAccepted=true&OpaqueBlob=TODOCustomDataFromAzureAD";
		}
	}
</script>`))
	})

	r.Path("/EnrollmentServer/Discovery.svc").Methods("GET", "POST").HandlerFunc(DiscoveryHandler)
	r.Path("/EnrollmentServer/Policy.svc").Methods("POST").HandlerFunc(PolicyHandler)
	r.Path("/EnrollmentServer/Enrollment.svc").Methods("POST").HandlerFunc(EnrollHandler)
	r.Path("/ManagementServer/MDM.svc").Methods("POST").HandlerFunc(ManageHandler)

	// Start HTTPS Server
	log.Println("HTTPS server listening on port 443...")
	log.Fatal(http.ListenAndServeTLS(":443", "./certs/certificate.pem", "./certs/privatekey.pem", handlers.LoggingHandler(os.Stdout, global(r))))
}

// global is a HTTP middleware that sets some default HTTP headers.
// This is not MDM related.
func global(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Custom HTTP Headers
		w.Header().Set("Server", "Windows-MDM-Demo")
		w.Header().Set("X-Creator", "Oscar Beaumont")

		// Continue With The Normal HTTP Handler
		h.ServeHTTP(w, r)
	})
}
