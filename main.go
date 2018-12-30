package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

func GetChar(r io.Reader) (byte, error) {
	buf := make([]byte, 1)
	if n, err := r.Read(buf); n == 0 || err != nil {
		if err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	return buf[0], nil
}

func ReadPassword(prompt string) (string, error) {
	r := os.Stdin
	w := os.Stdout
	fmt.Fprint(w, prompt)
	var pass []byte
	// Redirect input to mask password input
	state, errs := terminal.MakeRaw(int(r.Fd()))
	if errs != nil {
		return string(pass), errs
	}
	// Defer restoration of input reader
	defer func() {
		terminal.Restore(int(r.Fd()), state)
		fmt.Fprintln(w)
	}()

	// Read password
	maxLength := 1024

	var counter int
	var err error

	for counter = 0; counter <= maxLength; counter++ {
		if v, e := GetChar(r); e != nil {
			err = e
			break
		} else if v == 127 || v == 8 {
			if l := len(pass); l > 0 {
				pass = pass[:l-1]
				fmt.Fprint(w, "*")
			}
		} else if v == 13 || v == 10 {
			break
		} else if v == 3 {
			err = errors.New("Interrupted")
			break
		} else if v != 0 {
			pass = append(pass, v)
			fmt.Fprint(w, "*")
		}
	}
	return string(pass), err
}
func main() {
	var help bool
	flag.BoolVar(&help, "help", false, "Show script help")
	var API string
	var CLUSTER string
	var USER string
	var NS string
	var INSECURE_SSL bool
	flag.StringVar(&API, "api", "", "PKS APi key")
	flag.StringVar(&CLUSTER, "cluster", "", "Kubernetes cluster mater")
	flag.StringVar(&USER, "user", "", "LDAP username to connect to the cluster")
	flag.StringVar(&NS, "ns", "default", "LDAP namespece associated with this user")
	flag.BoolVar(&INSECURE_SSL, "insecure-ssl", true, "Accept/Ignore all server SSL certificates")
	flag.Parse()
	if help {
		flag.Usage()
		os.Exit(0)
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
	password, err := ReadPassword("Password: ")
	if err != nil {
		log.Fatalf("Error reading password %s", err.Error())
		os.Exit(-1)
	}
	//log.Printf("PWD: %s", password)
	kubernetes := NewKubernetesCmd(API, USER, CLUSTER, NS, password, INSECURE_SSL)
	err = kubernetes.Authenticate()
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
