# About

This tool will grab the relevant tokens and certificate data for a PKS cluster and configure the user to login to it.

# Basic Quickstart

To run directly, simply execute the binary with the required and optional flags:

`kubectl-pkstoken -api=api.pks.fullerton.cf-app.com -cluster=ldap.pks.exaforge.com -user=euler -ns=default -kubeconfig=myconfig`

* -api: the hostname of the PKS API
* -cluster: name of the k8s cluster
* -user: OIDC username
* -ns: which namespace should be configured
* -kubeconfig (optional): write to a specific file rather than default kubeconfig 


## To run  as a kubectl plugin (linux/mac only):
```sh
cp kubectl-pkstoken /usr/local/bin
```
(or anywhere in your `$PATH`)

then run 
```sh
kubectl pkstoken
```

## Dont forget to add a Role and Binding for the user like this:

```yaml
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  namespace: default
  name: ns-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: ns-admins
  namespace: default
subjects:
  - kind: User
    name: "euler"
roleRef:
  kind: Role
  name: ns-admin
  apiGroup: rbac.authorization.k8s.io

```

---
# Developer Instruction:

## Install dependencies
Install go crypto terminal library for password masking
```sh 
$ go get -t golang.org/x/crypto/ssh/terminal
```

# Compile to binary
Your can also compile to binaries as
``` sh
$ go build -o kubectl-pkstoken  main.go kubenetes.go
```

