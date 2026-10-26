// RSS adapter for Fleet's simulated devices. Upstream owns codecs and protocol sessions.
package mdmtest

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	microsoft "github.com/fleetdm/fleet/v4/server/mdm/microsoft"
	"github.com/fleetdm/fleet/v4/server/mdm/nanomdm/mdm"
	"github.com/micromdm/plist"
	"github.com/smallstep/pkcs7"
)

type ExternalApple struct {
	CheckInURL, Topic, Subject string
	Profiles                   map[string]map[string]any
}
type ExternalWindows struct {
	DiscoveryURL, PolicyURL, EnrollmentURL, ManagementURL, Username, Password string
	key                                                                       *rsa.PrivateKey
	csr                                                                       string
	identity                                                                  *tls.Certificate
	clientName, clientPassword, serverName, serverPassword, serverNonce       string
	Values                                                                    map[string]string
}

func externalHTTP(identity *tls.Certificate) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if identity != nil {
		t.TLSClientConfig.Certificates = []tls.Certificate{*identity}
	}
	return &http.Client{Transport: t, Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}
func externalDo(method, endpoint, content string, body []byte, identity *tls.Certificate) (*http.Response, error) {
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", content)
	resp, err := externalHTTP(identity).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: HTTP %d", method, req.URL.Path, resp.StatusCode)
	}
	return resp, nil
}

// NewExternalApple reads the actual CMS enrollment profile, including independent check-in URL.
func NewExternalApple(profile []byte) (*TestAppleMDMClient, error) {
	if p, err := pkcs7.Parse(profile); err == nil {
		profile = p.Content
	}
	var doc struct{ PayloadContent []map[string]any }
	if err := plist.Unmarshal(profile, &doc); err != nil {
		return nil, err
	}
	info := AppleEnrollInfo{}
	external := &ExternalApple{}
	for _, p := range doc.PayloadContent {
		switch p["PayloadType"] {
		case "com.apple.security.scep":
			q := p["PayloadContent"].(map[string]any)
			info.SCEPURL, _ = q["URL"].(string)
			info.SCEPChallenge, _ = q["Challenge"].(string)
			// RSS's issued identity binds the exact profile CN, rather than the simulated UDID.
			subject := q["Subject"].([]any)
			for _, rdn := range subject {
				for _, entry := range rdn.([]any) {
					v := entry.([]any)
					if v[0] == "CN" {
						external.Subject = v[1].(string)
					}
				}
			}
		case "com.apple.mdm":
			info.MDMURL, _ = p["ServerURL"].(string)
			external.CheckInURL, _ = p["CheckInURL"].(string)
			external.Topic, _ = p["Topic"].(string)
		}
	}
	if info.MDMURL == "" || info.SCEPURL == "" || external.CheckInURL == "" || external.Subject == "" || external.Topic == "" {
		return nil, fmt.Errorf("incomplete native enrollment profile")
	}
	c := NewTestMDMClientAppleDirect(info, "MacBookPro18,3")
	c.External = external
	c.OSVersion = "15.7.1"
	return c, nil
}
func (c *TestAppleMDMClient) externalRequest(content string, payload map[string]any) (*http.Response, error) {
	endpoint := c.EnrollInfo.MDMURL
	if _, ok := payload["MessageType"]; ok {
		endpoint = c.External.CheckInURL
	}
	if _, ok := payload["Topic"]; ok {
		payload["Topic"] = c.External.Topic
	}
	if payload["MessageType"] == "Authenticate" {
		payload["OSVersion"] = c.OSVersion
	}
	body, err := plist.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if c.scepCert == nil || c.scepKey == nil {
		return nil, fmt.Errorf("SCEP identity missing")
	}
	identity := tls.Certificate{Certificate: [][]byte{c.scepCert.Raw}, PrivateKey: c.scepKey}
	return externalDo("PUT", endpoint, content, body, &identity)
}

func NewExternalWindows(discovery, username, password, device string) (*TestWindowsMDMClient, error) {
	u, err := url.Parse(discovery)
	if err != nil {
		return nil, err
	}
	c := NewTestMDMClientWindowsProgramatic(u.Scheme+"://"+u.Host, "")
	c.DeviceID = device
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: c.DeviceID}}, key)
	if err != nil {
		return nil, err
	}
	c.External = &ExternalWindows{DiscoveryURL: discovery, Username: username, Password: password, key: key, csr: base64.StdEncoding.EncodeToString(csr)}
	return c, nil
}
func xmlText(s string) string { var b bytes.Buffer; xml.EscapeText(&b, []byte(s)); return b.String() }

var securityToken = regexp.MustCompile(`(?s)<wsse:BinarySecurityToken[^>]*>.*?</wsse:BinarySecurityToken>`)
var csrToken = regexp.MustCompile(`(?s)(<wsse:BinarySecurityToken ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"[^>]*>).*?(</wsse:BinarySecurityToken>)`)
var toElement = regexp.MustCompile(`(?s)(<a:To[^>]*>).*?(</a:To>)`)

func (c *TestWindowsMDMClient) externalRequest(path string, body []byte) (*http.Response, error) {
	e := c.External
	endpoint := e.DiscoveryURL
	content := "application/soap+xml; charset=utf-8"
	switch path {
	case microsoft.MDE2DiscoveryPath:
	case microsoft.MDE2PolicyPath:
		endpoint = e.PolicyURL
	case microsoft.MDE2EnrollPath:
		endpoint = e.EnrollmentURL
	case microsoft.MDE2ManagementPath:
		endpoint = e.ManagementURL
		content = "application/vnd.syncml.dm+xml"
	default:
		return nil, fmt.Errorf("unexpected upstream Windows path")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("server did not advertise endpoint")
	}
	wire := string(body)
	if path == microsoft.MDE2ManagementPath {
		// Fleet constructs Target with its own constant; honor the provisioning document instead.
		wire = strings.ReplaceAll(wire, c.fleetServerURL+microsoft.MDE2ManagementPath, xmlText(endpoint))
		// The RSS endpoint uses certificate authentication; remove Fleet's MD5 credential header.
		wire = regexp.MustCompile(`(?s)<Cred>.*?</Cred>`).ReplaceAllString(wire, "")
		basic := base64.StdEncoding.EncodeToString([]byte(e.clientName + ":" + e.clientPassword))
		wire = strings.Replace(wire, "</SyncHdr>", `<Cred><Meta><Format xmlns="syncml:metinf">b64</Format><Type xmlns="syncml:metinf">syncml:auth-basic</Type></Meta><Data>`+basic+`</Data></Cred></SyncHdr>`, 1)
		if !strings.Contains(wire, "<Final") {
			wire = strings.Replace(wire, "</SyncBody>", "<Final/></SyncBody>", 1)
		}
	} else {
		wire = toElement.ReplaceAllString(wire, "${1}"+xmlText(endpoint)+"${2}")
		if path == microsoft.MDE2DiscoveryPath {
			wire = strings.Replace(wire, "<EmailAddress></EmailAddress>", "<EmailAddress>"+xmlText(e.Username)+"</EmailAddress>", 1)
		} else {
			token := "<wsse:UsernameToken u:Id=\"rss-client\"><wsse:Username>" + xmlText(e.Username) + "</wsse:Username><wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText\">" + xmlText(e.Password) + "</wsse:Password></wsse:UsernameToken>"
			wire = securityToken.ReplaceAllStringFunc(wire, func(s string) string {
				if strings.Contains(s, "#PKCS10") {
					return s
				}
				return token
			})
			wire = csrToken.ReplaceAllString(wire, "${1}"+e.csr+"${2}")
			// OnPremise certificate profile selected by administrator is Device.
			wire = strings.Replace(wire, "<ac:Value>Full</ac:Value>", "<ac:Value>Device</ac:Value>", 1)
		}
	}
	resp, err := externalDo("POST", endpoint, content, []byte(wire), e.identity)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(raw) > 8*1024*1024 {
		return nil, fmt.Errorf("protocol response too large")
	}
	if bytes.Contains(bytes.ToLower(raw), []byte(":fault")) {
		return nil, fmt.Errorf("SOAP fault at %s", path)
	}
	if path == microsoft.MDE2DiscoveryPath {
		// XML namespace prefixes vary; decode names by their local names.
		dec := xml.NewDecoder(bytes.NewReader(raw))
		for {
			t, er := dec.Token()
			if er == io.EOF {
				break
			}
			if er != nil {
				return nil, er
			}
			if s, ok := t.(xml.StartElement); ok && (s.Name.Local == "EnrollmentPolicyServiceUrl" || s.Name.Local == "EnrollmentServiceUrl") {
				var value string
				if er = dec.DecodeElement(&value, &s); er != nil {
					return nil, er
				}
				if s.Name.Local == "EnrollmentPolicyServiceUrl" {
					e.PolicyURL = value
				} else {
					e.EnrollmentURL = value
				}
			}
		}
	}
	if path == microsoft.MDE2EnrollPath {
		var soap ExternalSOAPResponse
		if err = xml.Unmarshal(raw, &soap); err != nil {
			return nil, err
		}
		encoded := soap.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.Content
		prov, er := base64.StdEncoding.DecodeString(encoded)
		if er != nil {
			return nil, er
		}
		var doc fleet.WapProvisioningDoc
		if er = xml.Unmarshal(prov, &doc); er != nil {
			return nil, er
		}
		var leaf []byte
		var walk func(fleet.Characteristic)
		walk = func(ch fleet.Characteristic) {
			for _, p := range ch.Params {
				if p.Name == "EncodedCertificate" {
					if der, er := base64.StdEncoding.DecodeString(p.Value); er == nil {
						if cert, er := x509.ParseCertificate(der); er == nil && cert.PublicKeyAlgorithm == x509.RSA {
							pub := cert.PublicKey.(*rsa.PublicKey)
							if pub.N.Cmp(e.key.N) == 0 {
								leaf = der
							}
						}
					}
				}
				if p.Name == "ADDR" && strings.HasPrefix(p.Value, "https://") {
					e.ManagementURL = p.Value
				}
			}
			for _, child := range ch.Characteristics {
				walk(child)
			}
		}
		for _, ch := range doc.Characteristics {
			walk(ch)
		}
		var auth func(fleet.Characteristic)
		auth = func(ch fleet.Characteristic) {
			if ch.Type == "APPAUTH" {
				p := map[string]string{}
				for _, v := range ch.Params {
					p[v.Name] = v.Value
				}
				if p["AAUTHLEVEL"] == "APPSRV" {
					e.clientName = p["AAUTHNAME"]
					e.clientPassword = p["AAUTHSECRET"]
				}
				if p["AAUTHLEVEL"] == "CLIENT" {
					e.serverName = p["AAUTHNAME"]
					e.serverPassword = p["AAUTHSECRET"]
					nonce, er := base64.StdEncoding.DecodeString(p["AAUTHDATA"])
					if er == nil {
						e.serverNonce = string(nonce)
					}
				}
			}
			for _, child := range ch.Characteristics {
				auth(child)
			}
		}
		for _, ch := range doc.Characteristics {
			auth(ch)
		}
		if len(leaf) == 0 || e.ManagementURL == "" {
			return nil, fmt.Errorf("provisioning omitted matching certificate or management URL")
		}
		identity := tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: e.key}
		e.identity = &identity
	}
	if path == microsoft.MDE2ManagementPath {
		var reply fleet.SyncML
		if err = xml.Unmarshal(raw, &reply); err != nil {
			return nil, err
		}
		h := md5.Sum([]byte(e.serverName + ":" + e.serverPassword))
		d := md5.Sum([]byte(base64.StdEncoding.EncodeToString(h[:]) + ":" + e.serverNonce))
		if reply.SyncHdr.Cred == nil || reply.SyncHdr.Cred.Data != base64.StdEncoding.EncodeToString(d[:]) {
			return nil, fmt.Errorf("server SyncML digest authentication failed")
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp, nil
}

func (c *TestWindowsMDMClient) ExternalAcknowledge(cmds map[string]fleet.ProtoCmdOperation) error {
	var failure error
	msg, _ := c.lastManagementResp.GetMessageID()
	next := 1
	c.AppendResponse(fleet.SyncMLCmd{XMLName: xml.Name{Local: "Status"}, CmdID: fleet.CmdID{Value: strconv.Itoa(next)}, MsgRef: &msg, CmdRef: stringPtr("0"), Cmd: stringPtr("SyncHdr"), Data: stringPtr("212")})
	if c.External.Values == nil {
		c.External.Values = map[string]string{
			"./DevDetail/SwV": "10.0.22631.4460", "./Vendor/MSFT/DeviceStatus/OS/Edition": "48",
			"./DevDetail/Ext/Microsoft/DeviceName": "FLEET-WINDOWS", "./DevInfo/Man": "Fleet Test Vendor",
			"./DevDetail/Ext/Microsoft/OSPlatform": "Windows 11 Enterprise", "./DevInfo/Mod": "Fleet Simulated PC",
			"./DevDetail/FwV": "Fleet-Firmware-1.0", "./DevDetail/Ext/Microsoft/ProcessorArchitecture": "9",
			"./DevDetail/Ext/Microsoft/TotalRAM": "16384", "./DevDetail/Ext/Microsoft/SMBIOSSerialNumber": "FLEET-WIN-SERIAL-3028",
			"./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram":                    "FleetApp",
			"./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/FleetApp":           "Name/Publisher/Version/RegKey/Source",
			"./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/FleetApp/Name":      "Fleet MDM Test App",
			"./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/FleetApp/Publisher": "Fleet Test Publisher",
			"./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/FleetApp/Version":   "1.2.3",
			"./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/FleetApp/RegKey":    "HKLM\\Software\\FleetMDMTest",
			"./Device/Vendor/MSFT/Win32AppInventory/Win32InstalledProgram/FleetApp/Source":    "msi",
		}
	}
	var ack func(string, fleet.SyncMLCmd)
	ack = func(verb string, cmd fleet.SyncMLCmd) {
		if verb == "Status" {
			return
		}
		if verb != "Sequence" && verb != "Atomic" && verb != "Add" && verb != "Replace" && verb != "Delete" && verb != "Get" {
			failure = fmt.Errorf("unsupported simulated Windows command %s", verb)
			return
		}
		next++
		if verb == "Add" || verb == "Replace" {
			for _, item := range cmd.Items {
				if item.Target != nil && item.Data != nil {
					c.External.Values[*item.Target] = item.Data.Content
				}
			}
		}
		if verb == "Delete" {
			for _, item := range cmd.Items {
				if item.Target != nil {
					delete(c.External.Values, *item.Target)
				}
			}
		}
		status := "200"
		if verb == "Get" {
			for _, item := range cmd.Items {
				if item.Target != nil {
					if _, ok := c.External.Values[*item.Target]; !ok {
						status = "404"
					}
				}
			}
		}
		c.AppendResponse(fleet.SyncMLCmd{XMLName: xml.Name{Local: "Status"}, CmdID: fleet.CmdID{Value: strconv.Itoa(next)}, MsgRef: &msg, CmdRef: stringPtr(cmd.CmdID.Value), Cmd: stringPtr(verb), Data: stringPtr(status)})
		if verb == "Get" {
			items := []fleet.CmdItem{}
			for _, item := range cmd.Items {
				if item.Target == nil {
					continue
				}
				uri := *item.Target
				value, ok := c.External.Values[uri]
				if !ok {
					continue
				}
				items = append(items, fleet.CmdItem{Source: stringPtr(uri), Data: &fleet.RawXmlData{Content: xmlText(value)}})
			}
			if len(items) > 0 {
				next++
				c.AppendResponse(fleet.SyncMLCmd{XMLName: xml.Name{Local: "Results"}, CmdID: fleet.CmdID{Value: strconv.Itoa(next)}, MsgRef: &msg, CmdRef: stringPtr(cmd.CmdID.Value), Items: items})
			}
		}
		for _, ch := range cmd.SequenceCommands {
			ack("Sequence", ch)
		}
		for _, ch := range cmd.AtomicCommands {
			ack("Atomic", ch)
		}
		for _, ch := range cmd.AddCommands {
			ack("Add", ch)
		}
		for _, ch := range cmd.ReplaceCommands {
			ack("Replace", ch)
		}
		for _, ch := range cmd.DeleteCommands {
			ack("Delete", ch)
		}
		for _, ch := range cmd.ExecCommands {
			ack("Exec", ch)
		}
	}
	ordered := []fleet.ProtoCmdOperation{}
	for _, op := range cmds {
		ordered = append(ordered, op)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, _ := strconv.Atoi(ordered[i].Cmd.CmdID.Value)
		b, _ := strconv.Atoi(ordered[j].Cmd.CmdID.Value)
		return a < b
	})
	for _, op := range ordered {
		ack(op.Verb, op.Cmd)
	}
	return failure
}
func stringPtr(s string) *string { return &s }

func (c *TestAppleMDMClient) externalOrganization() []string {
	if c.External != nil {
		return nil
	}
	return []string{"fleet-organization"}
}

// Decode SOAP by expanded element local names; RSS uses SOAP 1.2, whereas Fleet's server type fixes 1.1.
type ExternalSOAPResponse struct {
	Body struct {
		RequestSecurityTokenResponseCollection struct {
			RequestSecurityTokenResponse struct {
				RequestedSecurityToken struct {
					BinarySecurityToken struct {
						Content string `xml:",chardata"`
					} `xml:"BinarySecurityToken"`
				} `xml:"RequestedSecurityToken"`
			} `xml:"RequestSecurityTokenResponse"`
		} `xml:"RequestSecurityTokenResponseCollection"`
	} `xml:"Body"`
}

// Apply supported commands to simulated device state before acknowledging them.
func (c *TestAppleMDMClient) ExternalAcknowledge(cmd *mdm.Command) (*mdm.Command, error) {
	if cmd == nil {
		return nil, fmt.Errorf("no Apple command to acknowledge")
	}
	if c.External.Profiles == nil {
		c.External.Profiles = map[string]map[string]any{}
	}
	var envelope map[string]any
	if err := plist.Unmarshal(cmd.Raw, &envelope); err != nil {
		return nil, err
	}
	body := envelope["Command"].(map[string]any)
	payload := map[string]any{"Status": "Acknowledged", "UDID": c.UUID, "CommandUUID": cmd.CommandUUID}
	switch cmd.Command.RequestType {
	case "InstallProfile":
		raw := body["Payload"].([]byte)
		p, err := pkcs7.Parse(raw)
		if err != nil {
			return nil, err
		}
		var profile map[string]any
		if err = plist.Unmarshal(p.Content, &profile); err != nil {
			return nil, err
		}
		id, ok := profile["PayloadIdentifier"].(string)
		if !ok {
			return nil, fmt.Errorf("profile identifier missing")
		}
		c.External.Profiles[id] = profile
	case "RemoveProfile":
		delete(c.External.Profiles, body["Identifier"].(string))
	case "ProfileList":
		profiles := []map[string]any{}
		for _, p := range c.External.Profiles {
			p["IsManaged"] = true
			profiles = append(profiles, p)
		}
		payload["ProfileList"] = profiles
	case "DeviceInformation":
		available := map[string]any{"BuildVersion": "24G90", "OSVersion": c.OSVersion,
			"SupplementalBuildVersion": "24G90", "SupplementalOSVersionExtra": "", "ModelNumber": "FLEET-MAC-3028",
			"DeviceCapacity": float64(512), "AvailableDeviceCapacity": float64(256), "BatteryLevel": float64(0.75),
			"HostName": "fleet-mac.example.test", "LocalHostName": "fleet-mac", "WiFiMAC": "02:00:00:00:30:28", "EthernetMAC": "02:00:00:00:30:29", "ProductName": c.Model, "Model": c.Model, "ModelName": "MacBook Pro", "SerialNumber": c.SerialNumber, "DeviceName": "Fleet simulated Mac", "IsSupervised": true, "IsAppleSilicon": true, "UDID": c.UUID}
		answers := map[string]any{}
		queries, ok := body["Queries"].([]any)
		if !ok {
			return nil, fmt.Errorf("DeviceInformation queries missing")
		}
		for _, query := range queries {
			name := query.(string)
			v, ok := available[name]
			if !ok {
				continue
			}
			answers[name] = v
		}
		payload["QueryResponses"] = answers
	case "SecurityInfo":
		payload["SecurityInfo"] = map[string]any{"ManagementStatus": map[string]any{"EnrolledViaDEP": false, "UserApprovedEnrollment": true, "IsUserEnrollment": false}}
	case "InstalledApplicationList":
		payload["InstalledApplicationList"] = []map[string]any{{"Identifier": "com.example.fleet-mdmtest", "Name": "Fleet MDM Test App", "Version": "1.2.3", "ShortVersion": "1.2.3", "Path": "/Applications/FleetMDMTest.app"}}
	case "CertificateList":
		payload["CertificateList"] = []map[string]any{{"CommonName": c.External.Subject, "Data": c.scepCert.Raw, "IsIdentity": true}}
	case "UserList":
		payload["Users"] = []map[string]any{}
	case "DeviceConfigured":
	default:
		return nil, fmt.Errorf("unsupported simulated Apple command %s", cmd.Command.RequestType)
	}
	return c.sendAndDecodeCommandResponse(payload)
}

func (c *TestWindowsMDMClient) ExternalPoll() (map[string]fleet.ProtoCmdOperation, error) {
	cmds, err := c.StartManagementSession()
	if err != nil {
		return nil, err
	}
	if err = c.ExternalAcknowledge(cmds); err != nil {
		return nil, err
	}
	return c.SendResponse()
}

func (c *TestWindowsMDMClient) externalResponses() []fleet.SyncMLCmd {
	values := []fleet.SyncMLCmd{}
	for _, cmd := range c.queuedCommandResponses {
		values = append(values, cmd)
	}
	sort.Slice(values, func(i, j int) bool {
		a, _ := strconv.Atoi(values[i].CmdID.Value)
		b, _ := strconv.Atoi(values[j].CmdID.Value)
		return a < b
	})
	return values
}
