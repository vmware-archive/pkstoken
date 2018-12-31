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
 To run the program:
```sh
$ go run main.go kubenetes.go -api=<PKS-API-ENDPOINT> -cluster=<CLUSTER-EXTERNAL-NAME> -user=euler -ns=default
```
# Compile to binary
Your can also compile to binaries as
``` sh
$ go build -o kubnectl-pks-token  main.go kubenetes.go
```

# Dont forget to add a Role and Binding for the user like this:

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