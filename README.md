<img src="./devops/docs/logo.png" style="width:150px">

# cert-manager-sync

Enable Kubernetes `cert-manager` to sync TLS certificates to AWS ACM, HashiCorp Vault, Incapsula, and ThreatX.

## Architecture

![architecture](./devops/docs/cert-manager-sync.png)

## Background

In containerized environments, we use `cert-manager` to automatically provision, manage, and renew TLS certificates for our applications.

These certificates are managed entirely through code using git ops, and developers / operators never need to touch / see the actual plain-text certificate as it is automatically provisioned and attached to gateway.

However for applications that sit behind the Incapsula WAF, or have components in both EKS and CloudFront, there was not a seamless and secure process to attach certificates without operators manually passing DNS01 challenge records back and forth or worse, passing TLS certs back and forth. 

In addition to the security risk this poses, it also introduces a level of human error and manual tracking of expiry / renewals.

This operator fully automates this process, so that developers must only annotate their `cert-manager` kube tls secrets with a flag indicating they want the certificate synced and to where they want it synced.

When the certificate is provisioned by `cert-manager`, the `cert-manager-sync` operator will sync the certificate to the upstream certificate provider(s) defined in the TLS secret annotations.

## Authentication

### AWS ACM

Create an IRSA role with `acm:*` access, and attach the IAM Role to the k8s ServiceAccount in `devops/k8s/sa.yaml`.

### Incapsula

Create an Incapsula API Key and create a kube secret in the namespace in which the operator runs.

```bash
kubectl -n cert-manager \
	create secret generic example-incapsula-api-secret \
	--from-literal api_id=XXXXX --from-literal api_key=XXXXX
```

You will then annotate your k8s TLS secret with this secret name to tell the operator to retrieve the Incapsula API secret from this location.

### ThreatX

Create a ThreatX API Key and create a kube secret in the namespace in which the operator runs.

```bash
kubectl -n cert-manager \
	create secret generic example-threatx-api-secret \
	--from-literal api_token=XXXXX --from-literal customer_name=XXXXX
```

You will then annotate your k8s TLS secret with this secret name to tell the operator to retrieve the ThreatX API secret from this location.

### HashiCorp Vault

HashiCorp Vault relies on the [Kubernetes Auth Method](https://www.vaultproject.io/docs/auth/kubernetes) to securely issue the operator a short-lived token according to your Vault policy. This token is then used to sync the updated certs to Vault so that they can be used by Vault-integrated applications and services.

## Configuration

The operator uses Kubernetes annotations to define the sync locations and configurations.

The following example contains all supported annotations.

```yaml
---
apiVersion: v1
type: kubernetes.io/tls
kind: Secret
metadata:
  name: example
  namespace: cert-manager
  annotations:
    # enable sync on tls secret
    cert-manager-sync.lestak.sh/sync-enabled: "true"
    # Role ARN to assume if set
    cert-manager-sync.lestak.sh/assume-role-arn: ""
    # Region to use. If not set, will use AWS_REGION env var, or us-east-1 if not set
    cert-manager-sync.lestak.sh/aws-region: ""
    
    # ACM
    # sync certificate to ACM
    cert-manager-sync.lestak.sh/acm-enabled: "true" 
    # will be auto-filled by operator for in-place renewals
    cert-manager-sync.lestak.sh/acm-certificate-arn: ""
    
    # Secrets Manager
    # sync certificate to Secrets Manager
    cert-manager-sync.lestak.sh/asm-enabled: "true"
    # the name of secret assigned in secretsmanager. This cannot be empty.
    cert-manager-sync.lestak.sh/asm-name: ""
    # the description of secret assigned in secretsmanager. This can be empty.
    cert-manager-sync.lestak.sh/asm-description: ""
    # if a secretsmanager name (above) already exists, this will auto-filled
    cert-manager-sync.lestak.sh/asm-secret-arn: ""
    
    # other supported things
    cert-manager-sync.lestak.sh/incapsula-site-id: "12345" # incapsula site to attach cert
    cert-manager-sync.lestak.sh/incapsula-secret-name: "cert-manager-sync-poc" # secret in same namespace which contains incapsula api key
    cert-manager-sync.lestak.sh/threatx-hostname: "example.com" # threatx hostname to attach cert
    cert-manager-sync.lestak.sh/threatx-secret-name: "example-threatx-api-secret" # secret in same namespace which contains threatx api key
    cert-manager-sync.lestak.sh/vault-addr: "https://vault.example.com" # HashiCorp Vault address
    cert-manager-sync.lestak.sh/vault-role: "role-name" # HashiCorp Vault role name
    cert-manager-sync.lestak.sh/vault-auth-method: "auth-method" # HashiCorp Vault auth method name
    cert-manager-sync.lestak.sh/vault-path: "kv-name/path/to/secret" # HashiCorp Vault path to store cert
data:
  ca.crt: ""
  tls.crt: ""
  tls.key: ""
```

## Deployment

Create `regcred` registry credential secret in `cert-manager` namespace.

```bash

kubectl apply -f devops/k8s
```
