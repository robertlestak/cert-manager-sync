# GCP Certificate Manager Trust Store Integration

This document describes how to use cert-manager-sync to automatically sync CA certificates to Google Cloud Certificate Manager trust stores.

## Overview

GCP Certificate Manager trust stores allow you to store trusted CA certificates that can be used by load balancers and other GCP services for certificate validation. This feature is particularly useful for:

- Storing root CA certificates for custom PKI
- Managing intermediate CA certificates
- Automating trust store updates when CA certificates are renewed

## Prerequisites

1. A GCP project with Certificate Manager API enabled
2. A service account with `roles/certificatemanager.editor` permissions
3. cert-manager-sync deployed in your Kubernetes cluster

## Configuration

### Service Account Setup

Create a service account with the required permissions:

```bash
# Create service account
gcloud iam service-accounts create cert-manager-sync \
    --description="Service account for cert-manager-sync" \
    --display-name="cert-manager-sync"

# Grant Certificate Manager Editor role
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:cert-manager-sync@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/certificatemanager.editor"
```

### Kubernetes Configuration

For GKE with Workload Identity:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cert-manager-sync
  namespace: cert-manager
  annotations:
    iam.gke.io/gcp-service-account: cert-manager-sync@PROJECT_ID.iam.gserviceaccount.com
```

For non-GKE clusters, create a secret with service account credentials:

```bash
kubectl -n cert-manager create secret generic gcp-credentials \
  --from-file=GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
```

## Usage

### Root CA Certificate

To sync a root CA certificate to a trust store:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: root-ca
  namespace: cert-manager
  annotations:
    cert-manager-sync.lestak.sh/sync-enabled: "true"
    cert-manager-sync.lestak.sh/gcp-enabled: "true"
    cert-manager-sync.lestak.sh/gcp-project: "my-project"
    cert-manager-sync.lestak.sh/gcp-location: "us-central1"
    cert-manager-sync.lestak.sh/gcp-operation-type: "truststore"
    cert-manager-sync.lestak.sh/gcp-certificate-type: "root"
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-ca-certificate>
  tls.key: <base64-encoded-private-key>  # Optional
```

### Intermediate CA Certificate

To sync an intermediate CA certificate:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: intermediate-ca
  namespace: cert-manager
  annotations:
    cert-manager-sync.lestak.sh/sync-enabled: "true"
    cert-manager-sync.lestak.sh/gcp-enabled: "true"
    cert-manager-sync.lestak.sh/gcp-project: "my-project"
    cert-manager-sync.lestak.sh/gcp-location: "us-central1"
    cert-manager-sync.lestak.sh/gcp-operation-type: "truststore"
    cert-manager-sync.lestak.sh/gcp-certificate-type: "intermediate"
type: kubernetes.io/tls
data:
  tls.crt: <base64-encoded-intermediate-ca-certificate>
  tls.key: <base64-encoded-private-key>  # Optional
```

## Annotation Reference

| Annotation | Required | Description | Default |
|------------|----------|-------------|---------|
| `cert-manager-sync.lestak.sh/sync-enabled` | Yes | Enable cert-manager-sync | - |
| `cert-manager-sync.lestak.sh/gcp-enabled` | Yes | Enable GCP sync | - |
| `cert-manager-sync.lestak.sh/gcp-project` | Yes | GCP project ID | - |
| `cert-manager-sync.lestak.sh/gcp-location` | Yes | GCP location | - |
| `cert-manager-sync.lestak.sh/gcp-operation-type` | Yes | Set to "truststore" | "certificate" |
| `cert-manager-sync.lestak.sh/gcp-certificate-type` | No | "root" or "intermediate" | "root" |
| `cert-manager-sync.lestak.sh/gcp-trust-config-name` | No | Trust config name (auto-filled) | - |
| `cert-manager-sync.lestak.sh/gcp-secret-name` | No | Credentials secret name | - |

## Behavior

1. **First Sync**: Creates a new TrustConfig with the certificate
2. **Subsequent Syncs**: Updates the existing TrustConfig with the new certificate
3. **Certificate Type**: Determines whether the certificate is stored as a trust anchor (root) or intermediate CA
4. **Naming**: Trust config names are automatically generated as `projects/{project}/locations/{location}/trustConfigs/{namespace}-{secret-name}`

## Monitoring

Check the cert-manager-sync logs for sync status:

```bash
kubectl logs -n cert-manager deployment/cert-manager-sync
```

Successful sync will show:
```
INFO[...] trust store synced
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the service account has `roles/certificatemanager.editor`
2. **API Not Enabled**: Enable the Certificate Manager API in your GCP project
3. **Invalid Certificate**: Ensure the certificate is in valid PEM format

### Verification

Verify the trust config was created:

```bash
gcloud certificate-manager trust-configs list --location=us-central1
```

View trust config details:

```bash
gcloud certificate-manager trust-configs describe TRUST_CONFIG_NAME --location=us-central1
```
