package main

import (
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

	// Retrieve the MessageID From The Body For The Response
	// Note: The XML isn't parsed to keep this example simple but in your server it would have to have been
	// So ignore the strings.Replace and Regex stuff you wouldn't do it this way
	DeviceID := strings.Replace(strings.Replace(regexp.MustCompile(`<\/Target><Source><LocURI>[\s\S]*?<\/LocURI><\/Source>`).FindStringSubmatch(body)[0], "</Target><Source><LocURI>", "", -1), "</LocURI></Source>", "", -1)

	// Retrieve the SessionID From The Body For The Response
	// Note: The XML isn't parsed to keep this example simple but in your server it would have to have been
	// So ignore the strings.Replace and Regex stuff you wouldn't do it this way
	SessionID := strings.Replace(strings.Replace(regexp.MustCompile(`<SessionID>[\s\S]*?<\/SessionID>`).FindStringSubmatch(body)[0], "<SessionID>", "", -1), "</SessionID>", "", -1)

	// Retrieve the MsgID From The Body For The Response
	// Note: The XML isn't parsed to keep this example simple but in your server it would have to have been
	// So ignore the strings.Replace and Regex stuff you wouldn't do it this way
	MsgID := strings.Replace(strings.Replace(regexp.MustCompile(`<MsgID>[\s\S]*?<\/MsgID>`).FindStringSubmatch(body)[0], "<MsgID>", "", -1), "</MsgID>", "", -1)

	// Create response payload
	// A different response is need for AD so this is used to detect AD. This would be done by XML parsing the code not this for a production server.
	// This is done this way to keep the server simple and easy to understand for non Go Lang developers.
	var response string
	if strings.Contains(body, "com.microsoft/MDM/AADUserToken") {
		response = `<?xml version="1.0" encoding="UTF-8"?>
	<SyncML xmlns="SYNCML:SYNCML1.2">
		<SyncHdr>
			<VerDTD>1.2</VerDTD>
			<VerProto>DM/1.2</VerProto>
			<SessionID>` + SessionID + `</SessionID>
			<MsgID>` + MsgID + `</MsgID>
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
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>0</CmdRef>
				<Cmd>SyncHdr</Cmd>
				<Data>200</Data>
			</Status>
			<Status>
				<CmdID>2</CmdID>
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>2</CmdRef>
				<Cmd>Alert</Cmd>
				<Data>200</Data>
			</Status>
			<Status>
				<CmdID>3</CmdID>
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>3</CmdRef>
				<Cmd>Alert</Cmd>
				<Data>200</Data>
			</Status>
			<Status>
				<CmdID>4</CmdID>
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>4</CmdRef>
				<Cmd>Alert</Cmd>
				<Data>200</Data>
			</Status>
			<Status>
				<CmdID>5</CmdID>
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>5</CmdRef>
				<Cmd>Replace</Cmd>
				<Data>200</Data>
			</Status>
			<Final />
		</SyncBody>
	</SyncML>`
	} else {
		response = `<?xml version="1.0" encoding="UTF-8"?>
	<SyncML xmlns="SYNCML:SYNCML1.2">
		<SyncHdr>
			<VerDTD>1.2</VerDTD>
			<VerProto>DM/1.2</VerProto>
			<SessionID>` + SessionID + `</SessionID>
			<MsgID>` + MsgID + `</MsgID>
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
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>0</CmdRef>
				<Cmd>SyncHdr</Cmd>
				<Data>200</Data>
			</Status>
			<Status>
				<CmdID>2</CmdID>
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>2</CmdRef>
				<Cmd>Alert</Cmd>
				<Data>200</Data>
			</Status>
			<Status>
				<CmdID>3</CmdID>
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>3</CmdRef>
				<Cmd>Alert</Cmd>
				<Data>200</Data>
			</Status>
			<Status>
				<CmdID>4</CmdID>
				<MsgRef>` + MsgID + `</MsgRef>
				<CmdRef>4</CmdRef>
				<Cmd>Replace</Cmd>
				<Data>200</Data>
			</Status>
			<Final />
		</SyncBody>
	</SyncML>`
	}

	// Return request body
	responseRaw := []byte(strings.ReplaceAll(strings.ReplaceAll(response, "\n", ""), "\t", ""))
	w.Header().Set("Content-Type", "application/vnd.syncml.dm+xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(responseRaw)))
	w.Write(responseRaw)
}
