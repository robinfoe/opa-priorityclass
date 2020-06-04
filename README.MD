# Getting Started
This repo show how we can leverage on OPA to secure kubernetes cluster



## Install OPA

Create namespace and change the context

```bash 
kubectl create ns opa
kubens opa
```

Apply server certificate 

```bash 
# files located in ./setup
kubectl create secret tls opa-server --cert=server.crt --key=server.key 
```

Create label for namepsace to skip policy evaluation
 
```bash 
kubectl label ns kube-system openpolicyagent.org/webhook=ignore
kubectl label ns opa openpolicyagent.org/webhook=ignore
```

Deploy OPA
```bash 
# files located in ./setup
kubectl apply -f admission-controller.yaml 
kubectl apply -f webhook-configuration.yaml 
```

## Configure Policy 

Go to ./policy and run the following commands

```bash 
kubens opa

kubectl create configmap priority-class-whitelist --from-file priority-check.rego
```

## Test the policy
Go to ./kube and run the following commands



```bash 

## create priority class
kubectl create -f pc-cat-1.yaml
kubectl create -f pc-cat-2.yaml
kubectl create -f pc-cat-3.yaml

## Create test namespace
kubectl create -f ns-dev-parkconnect.yaml

## run the below 

## for deployment
kubectl create -f deployment-error.yaml
kubectl create -f deployment-ok.yaml

## for pod 
kubectl create -f pod-web-error.yaml
kubectl create -f pod-web-ok.yaml

```


