[![License][license-img]][license]
![Python](https://img.shields.io/badge/go-v1.19-blue.svg?style=plastic)
![Downloads][download]


# Kubesploit

<p align="left">
  <img src="https://github.com/cyberark/kubesploit/blob/assets/1.5x/kubesploit@1.5x-100_tiny.jpg?raw=true" height="30%" width="30%">
</p>


Kubesploit is a cross-platform post-exploitation HTTP/2 Command & Control server and agent dedicated for containerized environments written in Golang and built on top of [Merlin](https://github.com/Ne0nd0g/merlin) project by [Russel Van Tuyl (@Ne0nd0g)](https://github.com/Ne0nd0g).  

## Our Motivation
While researching Docker and Kubernetes, we noticed that most of the tools available today are aimed at passive scanning for vulnerabilities in the cluster, and there is a lack of more complex attack vector coverage.   
They might allow you to see the problem but not exploit it. It is important to run the exploit to simulate a real-world attack that will be used to determine corporate resilience across the network.   
When running an exploit, it will practice the organization's cyber event management, which doesn't happen when scanning for cluster issues.   
It can help the organization learn how to operate when real attacks happen, see if its other detection system works as expected and what changes should be made.   
We wanted to create an offensive tool that will meet these requirements.  

But we had another reason to create such a tool. We already had two open-source tools ([KubiScan](https://github.com/cyberark/KubiScan) and [kubeletctl](https://github.com/cyberark/kubeletctl)) related to Kubernetes, and we had an idea for more. 
Instead of creating a project for each one, we thought it could be better to make a new tool that will centralize the new tools, and this is when Kubesploit was created.

We searched for an open-source that provide that heavy lifting for a cross-platform system, and we found [Merlin](https://github.com/Ne0nd0g/merlin), 
written by [Russel Van Tuyl (@Ne0nd0g)](https://github.com/Ne0nd0g), to be suitable for us.  

Our main goal is to contribute to raising awareness about the security of containerized environments, and improve the mitigations implemented in the various networks.
All of this captured through a framework that provides the appropriate tools for the job of PT teams and Red Teamers during their activities in these environments.
Using these tools will help you estimate these environments' strengths and make the required changes to protect them.

## What's New
As the C&C and the agent infrastructure were done already by [Merlin](https://github.com/Ne0nd0g/merlin), we integrated [Go interpreter ("Yaegi")](https://github.com/traefik/yaegi) to be able to run Golang code from the server to the agent.  
It allowed us to write our modules in Golang, provide more flexibility on the modules, and dynamically load new modules.
It is an ongoing project, and we are planning to add more modules related to Docker and Kubernetes in the future.

The currently available modules are:  
- Container breakout using mounting

- Container breakout using docker.sock

- Container breakout using CVE-2019-5736 exploit

- Scan for Kubernetes cluster known CVEs

- Port scanning with focus on Kubernetes services

- Kubernetes service scan from within the container

- Light [kubeletctl](https://github.com/cyberark/kubeletctl) containing the following options:
  - Scan for containers with RCE
  - Scan for Pods and containers
  - Scan for tokens from all available containers
  - Run command with multiple options

- cGroup breakout

- Kernel module breakout

- Var log escape

- Deepce: Docker enumeration (Open-Source project integrated as a module)

- Vulnerability test: check which of kubesploit exploits your container is vulnerable to  

  **For detailed information about the modules, check the WiKi page**


## Quick Start
We created a dedicated [Kubernetes environment in Katacoda](https://www.katacoda.com/cyberarkcommons/scenarios/kubesploit) for you to experiment with Kubesploit.   
It’s a full simulation with a complete set of automated instructions on how to use Kubesploit. We encourage you to explore it.  

![kubesploit](https://github.com/cyberark/kubesploit/blob/assets/kubesploit_demo_with_progress_bar.gif)

## Build
To build this project, run the `make` command from the root folder. 

**NOTE:** Currently you'll need to use Golang 1.18 or Go 1.19 (the latest 2 major releases) based on the golang requirements that [traefik/yaegi v0.14.3](https://github.com/traefik/yaegi/tree/v0.14.3#features) have.

### Quick Build  
To run quick build for Linux, you can run the following:  
```
export PATH=$PATH:/usr/local/go/bin
go build -o agent cmd/merlinagent/main.go
go build -o server cmd/merlinserver/main.go
```
### Dockerizing
In order to run the _server_ using a container, you have to make the Kubesploit server listen on the `0.0.0.0` interface (and not `127.0.0.1`).
You can update the interface field in the [config.yaml](https://github.com/cyberark/kubesploit/blob/main/config.yaml).
> sidenote: make sure to bind ports between the host and container (the default port is `443` and it can be configured in the config.yaml as well)


## Mitigations 
### YARA rules
We created YARA rules that will help to catch Kubesploit binaries. The rules are written in the file `kubesploit.yara`.   

### Agent Recording  
Every Go module loaded to the agent is being recorded inside the victim machine.   

### MITRE map
We created a MITRE map of the vectors attack being used by Kubesploit.    

<p align="center">
  <img src="https://github.com/cyberark/kubesploit/blob/assets/mitre_pic_full.png" height="90%" width="120%">
</p>

### Mitigation for Modules  
For every module we created, we wrote its description and how to defend from it.  
We sum it up in the [MITIGATION.md](MITIGATION.md) file.

## Contributing

We welcome contributions of all kinds to this repository.  
For instructions on how to get started and descriptions
of our development workflows, please see our [contributing guide](https://github.com/cyberark/conjur-api-go/blob/master/CONTRIBUTING.md).

## Credit  

We want to thank Russel Van Tuyl (@Ne0nd0g) for creating [Merlin](https://github.com/Ne0nd0g/merlin) as an open-source that allowed us to build Kubesploit on top of it.   
We also want to thank Traefik Labs (@traefik) for creating [Go interpreter ("Yaegi")](https://github.com/traefik/yaegi) that allowed us to run the Golang modules on a remote agent easily.

## License
Copyright (c) 2021 CyberArk Software Ltd. All rights reserved.    
This repository is licensed under GPL-3.0 License.    
For the full license text see [`LICENSE`](LICENSE).  

## Share Your Thoughts And Feedback
For more comments, suggestions or questions, you can contact Eviatar Gerzi ([@g3rzi](https://twitter.com/g3rzi)) from CyberArk Labs or open an issue.
You can find more projects developed by us at https://github.com/cyberark/.


[license-img]: https://img.shields.io/github/license/cyberark/kubesploit.svg
[license]: https://github.com/cyberark/kubesploit/blob/master/LICENSE
[download]: https://img.shields.io/github/downloads/cyberark/kubesploit/total?logo=github
