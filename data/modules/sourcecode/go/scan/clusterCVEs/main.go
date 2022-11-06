package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type KubernetesVersion struct {
	Major      string `json:"major"`
	Minor      string `json:"minor"`
	GitVersion string `json:"gitVersion"`
}

type Version struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

type CVE struct {
	FixedVersions []Version
	Description   string
	CVENumber     string
}

var KNOWN_KUBERNETES_CVES = []CVE{
	struct {
		FixedVersions []Version
		Description   string
		CVENumber     string
	}{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 11,
				Patch: 8,
				Raw:   "1.11.8",
			},
			{
				Major: 1,
				Minor: 12,
				Patch: 6,
				Raw:   "1.12.6",
			},
			{
				Major: 1,
				Minor: 13,
				Patch: 4,
				Raw:   "1.13.4",
			},
		},
		Description: "Kubernetes API DoS Vulnerability.",
		CVENumber:   "CVE-2019-1002100",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 10,
				Patch: 11,
				Raw:   "1.10.11",
			},
			{
				Major: 1,
				Minor: 11,
				Patch: 5,
				Raw:   "1.11.5",
			},
			{
				Major: 1,
				Minor: 12,
				Patch: 3,
				Raw:   "1.12.3",
			},
		},
		Description: "Allow an unauthenticated user to perform privilege escalation and gain full admin privileges on a cluster.",
		CVENumber:   "CVE-2018-1002105",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 7,
				Patch: 0,
				Raw:   "1.7.0",
			},
			{
				Major: 1,
				Minor: 8,
				Patch: 0,
				Raw:   "1.8.0",
			},
			{
				Major: 1,
				Minor: 9,
				Patch: 0,
				Raw:   "1.9.0",
			},
			{
				Major: 1,
				Minor: 10,
				Patch: 0,
				Raw:   "1.10.0",
			},
			{
				Major: 1,
				Minor: 11,
				Patch: 0,
				Raw:   "1.11.0",
			},
			{
				Major: 1,
				Minor: 12,
				Patch: 0,
				Raw:   "1.12.0",
			},
			{
				Major: 1,
				Minor: 13,
				Patch: 9,
				Raw:   "1.13.9",
			},
			{
				Major: 1,
				Minor: 14,
				Patch: 5,
				Raw:   "1.14.5",
			},
			{
				Major: 1,
				Minor: 15,
				Patch: 2,
				Raw:   "1.15.2",
			},
		},
		Description: "Allowing users to read, modify, or delete cluster-wide custom resources \neven if they have RBAC permissions that extend only to namespace resources.",
		CVENumber:   "CVE-2019-11247",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 13,
				Patch: 12,
				Raw:   "1.13.12",
			},
			{
				Major: 1,
				Minor: 14,
				Patch: 8,
				Raw:   "1.14.8",
			},
			{
				Major: 1,
				Minor: 15,
				Patch: 5,
				Raw:   "1.15.5",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 2,
				Raw:   "1.16.2",
			},
		},
		Description: "Kubernetes billion laughs attack vulnerability that allows an attacker to perform a Denial-of-Service (DoS) \nattack on the Kubernetes API server by uploading a maliciously crafted YAML file.",
		CVENumber:   "CVE-2019-11253",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 15,
				Patch: 10,
				Raw:   "1.15.10",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 7,
				Raw:   "1.16.7",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 3,
				Raw:   "1.17.3",
			},
		},
		Description: "The Kubernetes API Server component in versions 1.1-1.14, and versions prior to 1.15.10, 1.16.7 " +
			"\nand 1.17.3 allows an authorized user who sends malicious YAML payloads to cause the kube-apiserver to consume excessive CPU cycles while parsing YAML.",
		CVENumber: "CVE-2019-11254",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 16,
				Patch: 11,
				Raw:   "1.16.11",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 7,
				Raw:   "1.17.7",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 4,
				Raw:   "1.18.4",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 2,
				Raw:   "1.16.2",
			},
		},
		Description: "The kubelet and kube-proxy were found to contain security issue \nwhich allows adjacent hosts to reach TCP and UDP services bound to 127.0.0.1 running on the node or in the node's network namespace." +
			"\nSuch a service is generally thought to be reachable only by other processes on the same host, \nbut due to this defeect, could be reachable by other hosts on the same LAN as the node, or by containers running on the same node as the service.",
		CVENumber: "CVE-2020-8558",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 16,
				Patch: 13,
				Raw:   "1.16.13",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 9,
				Raw:   "1.17.9",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 6,
				Raw:   "1.18.6",
			},
		},
		Description: "The Kubernetes kube-apiserver is vulnerable to an unvalidated redirect on proxied upgrade requests" +
			" \nthat could allow an attacker to escalate privileges from a node compromise to a full cluster compromise.",
		CVENumber: "CVE-2020-8559",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 19,
				Patch: 15,
				Raw:   "1.19.15",
			},
			{
				Major: 1,
				Minor: 20,
				Patch: 11,
				Raw:   "1.20.11",
			},
			{
				Major: 1,
				Minor: 21,
				Patch: 5,
				Raw:   "1.21.5",
			},
			{
				Major: 1,
				Minor: 22,
				Patch: 2,
				Raw:   "1.22.2",
			},
		},
		Description: "A security issue was discovered in Kubernetes where a user may be able to create a container with " +
			"subpath volume mounts to access files & directories outside of the volume, including on the host filesystem.",
		CVENumber: "CVE-2021-25741",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 22,
				Patch: 14,
				Raw:   "1.22.14",
			},
			{
				Major: 1,
				Minor: 23,
				Patch: 11,
				Raw:   "1.23.11",
			},
			{
				Major: 1,
				Minor: 24,
				Patch: 5,
				Raw:   "1.24.5",
			},
			{
				Major: 1,
				Minor: 25,
				Patch: 0,
				Raw:   "1.25.0",
			},
		},
		Description: "A security issue was discovered in Kubernetes that could allow Windows workloads to run as " +
			"ContainerAdministrator even when those workloads set the runAsNonRoot option to true.",
		CVENumber: "CVE-2021-25749",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 25,
				Patch: 1,
				Raw:   "1.25.1",
			},
			{
				Major: 1,
				Minor: 24,
				Patch: 5,
				Raw:   "1.24.5",
			},
			{
				Major: 1,
				Minor: 23,
				Patch: 11,
				Raw:   "1.23.11",
			},
			{
				Major: 1,
				Minor: 22,
				Patch: 14,
				Raw:   "1.22.14",
			},
		},
		Description: "A security issue was discovered in kube-apiserver that allows an aggregated API server to redirect client" +
			" traffic to any URL. This could lead to the client performing unexpected actions as well as forwarding" +
			" the client's API server credentials to third parties.",
		CVENumber: "CVE-2022-3172",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 21,
				Patch: 1,
				Raw:   "1.21.1",
			},
			{
				Major: 1,
				Minor: 20,
				Patch: 7,
				Raw:   "1.20.7",
			},
			{
				Major: 1,
				Minor: 19,
				Patch: 11,
				Raw:   "1.20.7",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 19,
				Raw:   "1.18.19",
			},
		},
		Description: "A security issue was discovered in Kubernetes where a user" +
			" may be able to redirect pod traffic to private networks on a Node.",
		CVENumber: "CVE-2021-25737",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 18,
				Patch: 18,
				Raw:   "1.18.18",
			},
			{
				Major: 1,
				Minor: 19,
				Patch: 10,
				Raw:   "1.19.10",
			},
			{
				Major: 1,
				Minor: 20,
				Patch: 6,
				Raw:   "1.20.6",
			},
			{
				Major: 1,
				Minor: 21,
				Patch: 0,
				Raw:   "1.21.0",
			},
		},
		Description: "A security issue was discovered in kube-apiserver that could allow node updates to bypass a " +
			"Validating Admission Webhook",
		CVENumber: "CVE-2021-25735",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 17,
				Patch: 13,
				Raw:   "1.17.13",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 10,
				Raw:   "1.18.10",
			},
			{
				Major: 1,
				Minor: 19,
				Patch: 3,
				Raw:   "1.19.3",
			},
		},
		Description: "In Kubernetes clusters using Ceph RBD as a storage provisioner, with logging level of at least 4, " +
			"Ceph RBD admin secrets can be written to logs. This occurs in kube-controller-manager's logs during provisioning of Ceph RBD " +
			"persistent claims.",
		CVENumber: "CVE-2020-8566",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 17,
				Patch: 16,
				Raw:   "1.17.16",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 14,
				Raw:   "1.18.14",
			},
			{
				Major: 1,
				Minor: 19,
				Patch: 6,
				Raw:   "1.19.6",
			},
			{
				Major: 1,
				Minor: 20,
				Patch: 0,
				Raw:   "1.20.0",
			},
		},
		Description: "In Kubernetes, if the logging level is to at least 9, " +
			"authorization and bearer tokens will be written to log files. " +
			"This can occur both in API server logs and client tool output like kubectl.",
		CVENumber: "CVE-2020-8565",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 17,
				Patch: 13,
				Raw:   "1.17.13",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 10,
				Raw:   "1.18.10",
			},
			{
				Major: 1,
				Minor: 19,
				Patch: 3,
				Raw:   "1.19.3",
			},
		},
		Description: "In Kubernetes clusters using a logging level of at least 4, processing a malformed docker config file " +
			"will result in the contents of the docker config file being leaked, which can include pull secrets or" +
			" other registry credentials.",
		CVENumber: "CVE-2020-8564",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 19,
				Patch: 3,
				Raw:   "1.19.3",
			},
		},
		Description: "In Kubernetes clusters using VSphere as a cloud provider, with a logging level set to 4 or above," +
			" VSphere cloud credentials will be leaked in the cloud controller manager's log.",
		CVENumber: "CVE-2020-8563",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 16,
				Patch: 13,
				Raw:   "1.16.13",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 9,
				Raw:   "1.17.9",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 6,
				Raw:   "1.18.6",
			},
		},
		Description: "The /etc/hosts file mounted in a pod by kubelet is not included by the kubelet eviction manager " +
			"when calculating ephemeral storage usage by a pod. If a pod writes a large amount of data to the /etc/hosts file, " +
			"it could fill the storage space of the node and cause the node to fail.",
		CVENumber: "CVE-2020-8557",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 15,
				Patch: 2,
				Raw:   "1.15.2",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 9,
				Raw:   "1.16.9",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 5,
				Raw:   "1.17.5",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 1,
				Raw:   "1.18.1",
			},
		},
		Description: "There exists a Server Side Request Forgery (SSRF) vulnerability in kube-controller-manager " +
			"that allows certain authorized users to leak up to 500 bytes of arbitrary information from unprotected endpoints" +
			" within the master's host network (such as link-local or loopback services).",
		CVENumber: "CVE-2020-8555",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 16,
				Patch: 11,
				Raw:   "1.16.11",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 7,
				Raw:   "1.17.7",
			},
			{
				Major: 1,
				Minor: 18,
				Patch: 4,
				Raw:   "1.18.4",
			},
			{
				Major: 1,
				Minor: 19,
				Patch: 0,
				Raw:   "1.19.0",
			},
		},
		Description: "IPv4 only clusters susceptible to MitM attacks via IPv6 rogue router advertisements",
		CVENumber:   "CVE-2020-10749",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 15,
				Patch: 10,
				Raw:   "1.15.10",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 7,
				Raw:   "1.16.7",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 3,
				Raw:   "1.17.3",
			},
		},
		Description: "The Kubernetes API server has been found to be vulnerable to a denial of service attack via authorized" +
			" API requests.",
		CVENumber: "CVE-2020-8552",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 15,
				Patch: 10,
				Raw:   "1.15.10",
			},
			{
				Major: 1,
				Minor: 16,
				Patch: 7,
				Raw:   "1.16.7",
			},
			{
				Major: 1,
				Minor: 17,
				Patch: 3,
				Raw:   "1.17.3",
			},
		},
		Description: "The Kubelet has been found to be vulnerable to a denial of service attack via the kubelet API," +
			" including the unauthenticated HTTP read-only API typically served on port 10255, and the authenticated " +
			"HTTPS API typically served on port 10250.",
		CVENumber: "CVE-2020-8551",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 15,
				Patch: 4,
				Raw:   "1.15.4",
			},
		},
		Description: "A security issue was discovered in kubectl versions v1.13.10, v1.14.6, and v1.15.3. " +
			"The issue is of a medium severity and upgrading of kubectl is encouraged to fix the vulnerability.",
		CVENumber: "CVE-2019-11251",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 12,
				Patch: 10,
				Raw:   "1.12.10",
			},
			{
				Major: 1,
				Minor: 13,
				Patch: 8,
				Raw:   "1.13.8",
			},
			{
				Major: 1,
				Minor: 14,
				Patch: 4,
				Raw:   "1.14.4",
			},
			{
				Major: 1,
				Minor: 15,
				Patch: 0,
				Raw:   "1.15.0",
			},
		},
		Description: "The debugging endpoint /debug/pprof is exposed over the unauthenticated Kubelet healthz port. " +
			"Versions prior to 1.15.0, 1.14.4, 1.13.8, and 1.12.10 are affected.",
		CVENumber: "CVE-2019-11248",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 13,
				Patch: 9,
				Raw:   "1.13.9",
			},
			{
				Major: 1,
				Minor: 14,
				Patch: 5,
				Raw:   "1.14.5",
			},
			{
				Major: 1,
				Minor: 15,
				Patch: 2,
				Raw:   "1.15.2",
			},
		},
		Description: "A third issue was discovered with the Kubernetes kubectl cp command that could enable a directory " +
			"traversal such that a malicious container could replace or create files on a user’s workstation.",
		CVENumber: "CVE-2019-11249",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 13,
				Patch: 7,
				Raw:   "1.13.7",
			},
			{
				Major: 1,
				Minor: 14,
				Patch: 3,
				Raw:   "1.14.3",
			},
		},
		Description: " container uid changes to root after first restart or if image is already pulled to the node",
		CVENumber:   "CVE-2019-11245",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 12,
				Patch: 5,
				Raw:   "1.12.5",
			},
			{
				Major: 1,
				Minor: 13,
				Patch: 1,
				Raw:   "1.13.1",
			},
			{
				Major: 1,
				Minor: 15,
				Patch: 0,
				Raw:   "1.15.0",
			},
		},
		Description: " rest.AnonymousClientConfig() does not remove the serviceaccount credentials from " +
			"config created by rest.InClusterConfig()",
		CVENumber: "CVE-2019-11243",
	},
	{
		FixedVersions: []Version{
			{
				Major: 1,
				Minor: 11,
				Patch: 8,
				Raw:   "1.11.8",
			},
			{
				Major: 1,
				Minor: 12,
				Patch: 6,
				Raw:   "1.12.6",
			},
			{
				Major: 1,
				Minor: 13,
				Patch: 4,
				Raw:   "1.13.4",
			},
		},
		Description: "json-patch requests can exhaust apiserver resources",
		CVENumber:   "CVE-2019-1002100",
	},
}

func printCVE(cve CVE) {
	fmt.Printf("[*] ID: %s\n", cve.CVENumber)
	fmt.Printf("[*] Description: %s\n", cve.Description)
	var rawVersions strings.Builder
	fixedVersions := cve.FixedVersions
	for i, version := range fixedVersions {
		if i == len(cve.FixedVersions)-1 {
			rawVersions.WriteString(version.Raw)
		} else {
			rawVersions.WriteString(version.Raw + ", ")
		}
	}
	fmt.Printf("[*] Fixed versions: %s\n", rawVersions.String())
}

func exportVersionFromKubernetesCluster(address string) Version {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableCompression: true,
		MaxIdleConns:       10,
		IdleConnTimeout:    20 * time.Second,
	}

	client := &http.Client{Transport: tr}

	resp, err := client.Get(address)
	if err != nil {
		//log.Fatal("Failed with error: %s", err.Error())
		fmt.Println("Failed with error: %s", err.Error())
		return Version{}
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	var kubeVersion KubernetesVersion
	err = json.Unmarshal(body, &kubeVersion)

	if err != nil {
		//log.Fatal("Failed to parse JSON error: %s", err.Error())
		fmt.Println("Failed to parse JSON error: %s", err.Error())
		return Version{}
	}

	/*
		Support EKS version, example:
		  "major": "1",
		  "minor": "14+",
		  "gitVersion": "v1.14.9-eks-f459c0",
	*/

	newVersion := strings.Split(kubeVersion.GitVersion, ".")
	majorStr := strings.TrimPrefix(newVersion[0], "v")
	majorInt, err := strconv.Atoi(majorStr)
	if err != nil {
		//log.Fatal("Failed to parse major version with error: %s", err.Error())
		fmt.Println("Failed to parse major version with error: %s", err.Error())
		return Version{}
	}

	minorStr := strings.TrimSuffix(newVersion[1], "+")
	minorInt, err := strconv.Atoi(minorStr)
	if err != nil {
		//log.Fatal("Failed to parse minor version with error: %s", err.Error())
		fmt.Println("Failed to parse minor version with error: %s", err.Error())
		return Version{}
	}

	patchSplitted := strings.Split(newVersion[2], "-")
	patchInt, err := strconv.Atoi(patchSplitted[0])
	if err != nil {
		//log.Fatal("Failed to parse patch version with error: %s", err.Error())
		fmt.Println("Failed to parse patch version with error: %s", err.Error())
		return Version{}
	}

	return Version{
		Major: majorInt,
		Minor: minorInt,
		Patch: patchInt,
		Raw:   kubeVersion.GitVersion,
	}
}

func checkForVulnerabilitiesBaseOnVersion(currentVersion Version) {
	vulnerable := false
	isSmallerThanAll := 0
	knownCVEs := KNOWN_KUBERNETES_CVES
	for _, cve := range knownCVEs {
		fixedVersions := cve.FixedVersions
		for _, cveVersion := range fixedVersions {
			if currentVersion.Major == cveVersion.Major {
				if currentVersion.Minor == cveVersion.Minor {
					if currentVersion.Patch < cveVersion.Patch {
						vulnerable = true
					}
					break
				} else if currentVersion.Minor < cveVersion.Minor {
					isSmallerThanAll += 1
					if isSmallerThanAll == len(cve.FixedVersions) {
						vulnerable = true
						break
					}
				}
			}
		}

		if vulnerable {
			printCVE(cve)
			fmt.Println()
		}
	}
}

func mainfunc(urlInput string) {
	// The Run() function in ../pkg/modules/modules.go might return the URL with spaces, need to clean it
	urlInput = strings.TrimSpace(urlInput)
	urlInput = urlInput + "/version"

	fmt.Printf("[*] Scanning Kubernetes cluster: %s\n", urlInput)
	currentVersion := exportVersionFromKubernetesCluster(urlInput)
	if (Version{}) != currentVersion {
		fmt.Printf("[*] Current cluster version: %s\n\n", currentVersion.Raw)
		/*
			currentVersion = Version{
				Major: 1,
				Minor: 11,
				Patch: 3,
			}
		*/

		checkForVulnerabilitiesBaseOnVersion(currentVersion)
	}

	fmt.Println("[*] Done")
}
