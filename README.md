# Install dependencies
Install go crypto terminal library for password masking
```sh 
$ go get -t golang.org/x/crypto/ssh/terminal
```
# Running the app
Show Help
```sh 
$ go run main.go kubenetes.go --help
```
This is the implementation of the shell script provided. To run the program:
```sh
$ go run main.go kubenetes.go -api=api.pks.fullerton.cf-app.com -cluster=ldap.pks.exaforge.com -user=euler -ns=default
```
# Compile to binary
Your can also compile to binaries as
``` sh
$ go build -o autoconfig  main.go kubenetes.go
```

