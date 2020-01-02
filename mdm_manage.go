package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// ManageHandler is the HTTP handler assosiated with the mdm management service. This is what constantly pushes configuration to the device.
// It is at the URL: /ManagementServer/MDM.svc
func ManageHandler(w http.ResponseWriter, r *http.Request) {
	// Read The HTTP Request body
	bodyRaw, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	body := string(bodyRaw)

	fmt.Println(body) // TEMP

	// Retrieve the MessageID From The Body For The Response
	// Note: The XML isn't parsed to keep this example simple but in your server it would have to have been
	// So ignore the strings.Replace and Regex stuff you wouldn't do it this way
	DeviceID := strings.Replace(strings.Replace(regexp.MustCompile(`<\/Target><Source><LocURI>[\s\S]*?<\/LocURI><\/Source>`).FindStringSubmatch(body)[0], "</Target><Source><LocURI>", "", -1), "</LocURI></Source>", "", -1)

	fmt.Println(DeviceID)

	// Create response payload
	response := []byte(`<?xml version="1.0" encoding="utf-8" ?>
<SyncML xmlns="SYNCML:SYNCML1.2">
	<SyncHdr>
		<VerDTD>1.2</VerDTD>
		<VerProto>DM/1.2</VerProto>
		<SessionID>1</SessionID>
		<MsgID>2</MsgID>
		<Target>
			<LocURI>` + DeviceID + `</LocURI>
		</Target>
		<Source>
			<LocURI>https://` + domain + `/ManagementServer/MDM.svc</LocURI>
		</Source>
	</SyncHdr>
	<SyncBody>
		<Status>
			<CmdID>1</CmdID>
			<MsgRef>1</MsgRef>
			<CmdRef>2</CmdRef>
			<Cmd>Status</Cmd>
			<Data>200</Data>
		</Status>
		<Status>
			<CmdID>1</CmdID>
			<MsgRef>1</MsgRef>
			<CmdRef>3</CmdRef>
			<Cmd>Status</Cmd>
			<Data>200</Data>
		</Status>
		
		<Status>
			<CmdID>1</CmdID>
			<MsgRef>1</MsgRef>
			<CmdRef>4</CmdRef>
			<Cmd>Status</Cmd>
			<Data>200</Data>
		</Status>
		<Final />
	</SyncBody>
</SyncML>`)

	// Return request body
	w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.Write(response)

	// requestDump, err := httputil.DumpRequest(r, true)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println(string(requestDump))
}
