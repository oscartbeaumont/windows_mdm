package main

import (
	"log"
	"net/http"

	"github.com/oscartbeaumont/windows_mdm/mdm/windows/types"
)

// DiscoveryHandler is a http.Handler which handles the Windows request to discover the server.
// It first request this endpoint with a GET request and waits for a status 200 (Success) response
// It then posts to the endpoint to get the servers configuration
func DiscoveryHandler(ConfigDomain string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If the method is GET tell the client the server exists with a 200 response. Else the request is a POST return the server configuration.
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Decode The HTTP Request Body From The Client To The cmd varible using the struct defined above.
		var cmd windowstype.MdeDiscoveryRequest
		if err := cmd.Decode(r.Body); err != nil {
			panic(err) // TODO: Error Handling
		}

		// Use the verify function provided by the type to check it is correct
		if err := cmd.Verify(); err != nil {
			panic(err) // TODO: Error Handling
		}

		// Verify the server is the one the device thinks it is talking to. This is to prevent someone implementing a proxy with a different domain.
		// TODO: log.Println(cmd.Header.To.Host)

		// Verify the users email address is valid for the server's userbase.
		// TODO: log.Println(cmd.Body.Discover.Request.EmailAddress)

		// Log Action
		log.Println("User: " + cmd.Body.Discover.Request.EmailAddress + " Action: Discovery")

		// Create Response
		res := windowstype.Envelope{
			S:      "http://www.w3.org/2003/05/soap-envelope",
			A:      "http://www.w3.org/2005/08/addressing",
			Header: windowstype.NewHeader("http://schemas.microsoft.com/windows/management/2012/01/enrollment/IDiscoveryService/DiscoverResponse", cmd.Header.MessageID),
			Body: windowstype.Body{
				MdeDiscoveryResponse: windowstype.MdeDiscoveryResponse{
					AuthPolicy:                 "OnPremise",
					EnrollmentVersion:          "4.0",
					EnrollmentPolicyServiceURL: "https://" + ConfigDomain + "/EnrollmentServer/PolicyService.svc",     // TODO: Use propper url package for generation
					EnrollmentServiceURL:       "https://" + ConfigDomain + "/EnrollmentServer/EnrollmentService.svc", // TODO: Use propper url package for generation
				},
			},
		}

		// Send Response To The Client
		if err := res.Encode(w); err != nil {
			panic(err) // TODO: Error Handling
		}
	}
}
