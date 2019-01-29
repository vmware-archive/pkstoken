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
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type KubernetesCmd struct {
	idToken          string
	refreshToken     string
	accessToken      string
	Api              string
	User             string
	Password         string
	kubeconfig       string
	Cluster          string
	ClusterNamespace string
	UseInsecureCerts bool
	netClient        http.Client
}

func NewKubernetesCmd(api, username, cluster, namespace, kubeconfig string, password string, insecureSsl bool) KubernetesCmd {
	config := &tls.Config{
		InsecureSkipVerify: insecureSsl,
	}
	tr := &http.Transport{TLSClientConfig: config}
	return KubernetesCmd{
		UseInsecureCerts: insecureSsl,
		Api:              api,
		User:             username,
		Cluster:          cluster,
		kubeconfig:       kubeconfig,
		ClusterNamespace: namespace,
		Password:         password,
		netClient: http.Client{
			Transport: tr,
		},
	}
}

// https://api.pks.woodlake.cf-app.com:8443/oauth/token -sk -X POST -H 'Accept: application/json' -d '{"client_id":"pks_cluster_client","client_secret":"","grant_type":"password","username":"euler","password":"password","response_type":"id_token"}'
func (kc *KubernetesCmd) Authenticate() error {
	urls := fmt.Sprintf("https://%s:8443", kc.Api)
	data := url.Values{}
	data.Add("client_id", "pks_cluster_client")
	data.Add("client_secret", "")
	data.Add("grant_type", "password")
	data.Add("username", kc.User)
	data.Add("password", kc.Password)
	data.Add("response_type", "id_token")

	u, _ := url.ParseRequestURI(urls)
	u.Path = "/oauth/token"
	urlStr := u.String()

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	response, rerr := kc.netClient.Do(req)
	if rerr != nil {
		return rerr
	}
	responseData := make(map[string]interface{})
	err = json.NewDecoder(response.Body).Decode(&responseData)
	if err != nil {
		return err
	}
	bb, _ := json.Marshal(responseData)
	//log.Printf("Response: %s", string(bb))
	if response.StatusCode == 200 {
		idtoken, _ := responseData["id_token"]
		accessToken, _ := responseData["access_token"]
		refresh, _ := responseData["refresh_token"]
		kc.idToken = idtoken.(string)
		kc.refreshToken = refresh.(string)
		kc.accessToken = accessToken.(string)
		return nil
	} else {
		return errors.New(string(bb))
	}

}

func (kc KubernetesCmd) ConfigureCluster(certFile string) error {
	serverUrl := fmt.Sprintf("https://%s:8443", kc.Cluster)
	res, err := kc.ExecuteCommand("config", "set-cluster", kc.Cluster, "--server", serverUrl, "--certificate-authority", certFile, "--insecure-skip-tls-verify=false", "--embed-certs=true")
	if err != nil {
		log.Printf("Configure cert :%s", err.Error())
		return err
	}
	log.Println(res)
	res, err = kc.ExecuteCommand("config", "set-context", kc.Cluster, "--cluster", kc.Cluster, "--user", kc.User, "--namespace", kc.ClusterNamespace)
	if err != nil {
		log.Printf("Configure context %s", err.Error())
		return err
	}
	log.Println(res)
	res, err = kc.ExecuteCommand("config", "use-context", kc.Cluster)
	log.Println(res)

	log.Printf("Deleting certificate temp file %s", certFile)
	defer os.Remove(certFile)
	return err
}
func (kc KubernetesCmd) GoConfig() error {

	return nil
}
func (kc KubernetesCmd) ExportFile() error {
	serverUrl := fmt.Sprintf("https://%s:8443/%s", kc.Api, "oauth/token")
	res, err := kc.ExecuteCommand("config", "set-credentials", kc.User,
		"--auth-provider=oidc",
		"--auth-provider-arg=client-id=pks_cluster_client",
		"--auth-provider-arg=cluster_client_secret=",
		fmt.Sprintf("--auth-provider-arg=id-token=%s", kc.idToken),
		fmt.Sprintf("--auth-provider-arg=idp-issuer-url=%s", serverUrl),
		fmt.Sprintf("--auth-provider-arg=refresh-token=%s", kc.refreshToken))
	if err != nil {
		return err
	}
	log.Printf("Configuration: %s", res)
	return nil
}

/**
* Generate certificate file. Returns certificate filename
 */
func (kc KubernetesCmd) GetCertificate() string {
	urlS := fmt.Sprintf("https://%s:8443", kc.Cluster)
	response, err := kc.netClient.Get(urlS)
	if err != nil {
		log.Printf("Error connecting :%s", err.Error())
		return ""
	}
	for _, c := range response.TLS.PeerCertificates {
		if c.IsCA {
			//log.Print(string(c.Raw))
			certOut, _ := ioutil.TempFile("", "pks-token-cert-")
			//certOut, _ := os.Create(fmt.Sprintf("%s-cert.pem", kc.Cluster))
			err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
			if err != nil {
				log.Printf("Error generating certifciate %s", err.Error())
			}

			return fmt.Sprintf("%s", certOut.Name())
		}
	}
	return ""
}
func (kc KubernetesCmd) ExecuteCommand(command ...string) (string, error) {

	baseCommand := command
	if kc.kubeconfig != "" {
		baseCommand = append([]string{kc.kubeconfig}, baseCommand...)
		baseCommand = append([]string{"--kubeconfig"}, baseCommand...)
	}

	cmd := exec.Command("kubectl", baseCommand...) //Execute without kubeconfig option
	log.Printf("%v", cmd.Args)
	out, err := cmd.CombinedOutput()
	log.Print(string(out))
	return string(out), err
}
