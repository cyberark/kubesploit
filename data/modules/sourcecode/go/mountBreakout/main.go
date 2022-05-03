package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func extractDeviceType(deviceType string) (string,error) {
	var err error
	var device string

    if deviceType != "" {
		cmd := exec.Command("blkid")
		stdout, err := cmd.Output()
		if err == nil {
			//fmt.Println(string(stdout))
			lines := strings.Split(string(stdout), "\n")
			for _, line := range lines {
				if strings.Contains(line, "ext4") {
					deviceSplitted := strings.Split(line, ":")
					device = deviceSplitted[0]
					break
				}
			}
		}

	} else {
		foundUUID := false
		dat, err := ioutil.ReadFile("/proc/cmdline")
		if err == nil {
			cmdline := string(dat)
			splittedCmdLine := strings.Split(cmdline, " ")

			var uuid string

			// extracting the UUID of the device
			for _, splitLine := range splittedCmdLine {
				if strings.HasPrefix(splitLine, "root=UUID") || strings.HasPrefix(splitLine, "root=PARTUUID") {
					//uuid = splitLine[10:]
					split2 := strings.Split(splitLine, "=")
					uuid = split2[len(split2) - 1]
					foundUUID = true
				}
			}

			if foundUUID {
				cmd := exec.Command("blkid")
				stdout, err := cmd.Output()

				if err == nil {
					//fmt.Println(string(stdout))
					lines := strings.Split(string(stdout), "\n")
					for _, line := range lines {
						if strings.Contains(line, uuid) {
							deviceSplitted := strings.Split(line, ":")
							device = deviceSplitted[0]
						}
					}
				}
			}
		}
	}


	return device,err
}


// devices:
// /dev/sda1
// /dev/xvda1
func mainfunc(device string, useBruteforce string, deviceType string){
	var err error
	var devices []string
	// TODO: Need to remove 'device == "none"` and fix it inside the Run function in pkg/modules/modules.go.
	// It happens because when there is no value, it removed the array with the 'append' command.
	// The "none" is just a workaround for now
	if device == "" || device == "none" {
		if useBruteforce == "true" {

			fmt.Println("[*] Using brute force on known devices [\"/dev/sda1\", \"/dev/xvda1\"]")
			devices = append(devices, "/dev/sda1")
			devices = append(devices, "/dev/xvda1")
		} else {
			device,err = extractDeviceType(deviceType)
			if device == "" || err != nil {
				fmt.Println("[*] Didn't find device name, using brute force on known devices [\"/dev/sda1\", \"/dev/xvda1\"]")
				devices = append(devices, "/dev/sda1")
				devices = append(devices, "/dev/xvda1")
			} else {
				devices = append(devices, device)
			}
		}
	} else {
		devices = append(devices, device)
	}

	// creating folder
	dirId := 0
	var dirPath string

	// consider writing to /tmp if there is no permissions to write under /
	for {
		dirPath = "/mnt" + strconv.Itoa(dirId)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			os.Mkdir(dirPath, os.ModeDir)
			break
		} else {
			dirId += 1
		}
	}

	for _, deviceName := range devices {
		fmt.Printf("[*] Trying to mount \"%s\" to \"%s\"\n", deviceName, dirPath)
		cmd := exec.Command("mount", deviceName, dirPath)
		_, err = cmd.Output()
		if err != nil {
			fmt.Println(err.Error())
		} else {
			fmt.Printf("[*] Mounted successfuly \"%s\" to \"%s\"\n", deviceName, dirPath)
			fmt.Printf("[*] Host folder is in: \"%s\"\n", dirPath)
		}
	}
}

/*
func main(){
	mainfunc("", "false", "ext4")
   // mainfunc("/dev/sda1", "false")
   // mainfunc("", "true")
}*/
