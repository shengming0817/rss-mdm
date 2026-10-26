package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/fleetdm/fleet/v4/pkg/mdm/mdmtest"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mdm/nanomdm/mdm"
	"os"
)

type config struct{ Platform, Profile, DiscoveryURL, Username, Password, DeviceID string }
type input struct{ Action, CommandUUID string }

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: rss-mdmtest private-config.json")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var cfg config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		panic(err)
	}
	var apple *mdmtest.TestAppleMDMClient
	var windows *mdmtest.TestWindowsMDMClient
	if cfg.Platform == "macos" {
		raw, err = os.ReadFile(cfg.Profile)
		if err == nil {
			apple, err = mdmtest.NewExternalApple(raw)
		}
	} else {
		windows, err = mdmtest.NewExternalWindows(cfg.DiscoveryURL, cfg.Username, cfg.Password, cfg.DeviceID)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out := json.NewEncoder(os.Stdout)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	var commands map[string]fleet.ProtoCmdOperation
	var lastApple *mdm.Command
	for scanner.Scan() {
		var in input
		var result any
		err = json.Unmarshal(scanner.Bytes(), &in)
		if err == nil && apple != nil {
			var cmd *mdm.Command
			switch in.Action {
			case "enroll":
				err = apple.Enroll()
				result = map[string]any{"udid": apple.UUID, "serial": apple.SerialNumber}
			case "poll":
				cmd, err = apple.Idle()
				result = cmd
			case "ack":
				if lastApple == nil || lastApple.CommandUUID != in.CommandUUID {
					err = fmt.Errorf("Apple command correlation mismatch")
				} else {
					cmd, err = apple.ExternalAcknowledge(lastApple)
				}
				result = cmd
			case "state":
				result = apple.External.Profiles
			case "checkout":
				err = apple.Checkout()
			default:
				err = fmt.Errorf("unknown action")
			}
			if cmd != nil {
				lastApple = cmd
			}
		} else if err == nil {
			switch in.Action {
			case "enroll":
				err = windows.Enroll()
				result = map[string]any{"deviceID": windows.DeviceID}
			case "poll":
				commands, err = windows.ExternalPoll()
				result = commands
			case "ack":
				err = windows.ExternalAcknowledge(commands)
				if err == nil {
					commands, err = windows.SendResponse()
				}
				result = commands
			case "state":
				result = windows.External.Values
			case "unenroll":
				err = windows.Unenroll()
			default:
				err = fmt.Errorf("unknown action")
			}
		}
		if err != nil {
			out.Encode(map[string]any{"ok": false, "error": err.Error()})
		} else {
			out.Encode(map[string]any{"ok": true, "result": result})
		}
	}
}
