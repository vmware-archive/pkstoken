// pkstoken

// Copyright (c) 2018-Present Pivotal Software, Inc. All Rights Reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//    http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func usefile(path string) error {
	filename := path
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		_, err := os.Create(filename)
		if err != nil {
			return err
		}
	}
	log.Printf("using kubeconfig '%s'", filename)
	return nil
}

func main() {
	var help bool
	flag.BoolVar(&help, "help", false, "Show script help")
	var API string
	var CLUSTER string
	var USER string
	var KUBECONFIG string
	var NS string
	var INSECURE_SSL bool
	var password string

	flag.StringVar(&API, "api", "", "PKS API hostname")
	flag.StringVar(&CLUSTER, "cluster", "", "Kubernetes cluster master")
	flag.StringVar(&USER, "user", "", "LDAP username to connect to the cluster")
	flag.StringVar(&NS, "ns", "default", "namespece associated with this user")
	flag.StringVar(&KUBECONFIG, "kubeconfig", "", "Operate on a non default kubeconfig")
	flag.BoolVar(&INSECURE_SSL, "insecure-ssl", true, "Accept/Ignore all server SSL certificates")
	flag.Parse()
	if help {
		fmt.Println("This tool collects all required information to build a KUBECONFIG for LDAP/OIDC systems in Pivotal Container Service")
		flag.Usage()
		fmt.Println()
		fmt.Println("Copyright 2019 Pivotal")
		os.Exit(0)
	}

	if KUBECONFIG != "" {
		err := usefile(KUBECONFIG)
		if err != nil {
			log.Println(err.Error())
			os.Exit(-1)
		}
	}
	// Validate values are available
	commands := []string{"api", "cluster", "user", "ns"}
	allFound := true
	log.Printf("%-10s|%-40s|%-30s", "Command", "Value", "Default Value")
	for _, s := range commands {
		v := flag.Lookup(s)
		if len(v.Value.String()) == 0 {
			allFound = false
		}
		log.Printf("%-10s %-40s %-30s", v.Name, v.Value, v.DefValue)

	}
	if !allFound {
		log.Print("Invalid arguments")
		flag.Usage()
		os.Exit(-1)
	}

	// Read password
	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Printf("Password for user %s: ", USER)
		bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
		password = string(bytePassword)

		if err != nil {
			log.Fatalf("Error reading password %s", err.Error())
			os.Exit(-1)
		}
	} else {
		log.Fatalf("Not running in a TTY. Unable to prompt for password")
	}

	//log.Printf("PWD: %s", password)
	kubernetes := NewKubernetesCmd(API, USER, CLUSTER, NS, KUBECONFIG, password, INSECURE_SSL)
	err := kubernetes.Authenticate()
	if err != nil {
		log.Println(err.Error())
		os.Exit(-1)
	}
	log.Println("Authentication success")
	certFile := kubernetes.GetCertificate()
	if len(certFile) == 0 {
		log.Printf("Could not export certificate: %s", certFile)
		os.Exit(-1)
	}

	err = kubernetes.ConfigureCluster(certFile)
	if err != nil {
		log.Print(err.Error())
		os.Exit(-1)
	}

	err = kubernetes.ExportFile()
	if err != nil {
		log.Printf("Failed to export file %s", err.Error())
		os.Exit(-1)
	}
	log.Print("Configuration successful")
}
