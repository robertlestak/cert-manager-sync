# cert-manager-sync

![Version: 1.6.0](https://img.shields.io/badge/Version-1.6.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.6.0](https://img.shields.io/badge/AppVersion-1.6.0-informational?style=flat-square)

A Helm chart for cert-manager-sync

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` |  |
| autoscaling.enabled | bool | `false` |  |
| autoscaling.maxReplicas | int | `100` |  |
| autoscaling.minReplicas | int | `1` |  |
| autoscaling.targetCPUUtilizationPercentage | int | `80` |  |
| clusterRole.create | bool | `true` |  |
| config.acmAdoptExisting | string | `"false"` | Cluster-wide default for reusing an already-imported ACM certificate tagged for a secret instead of importing a new one. Leave `"false"` if two clusters sync same-named secrets into one AWS account — their tags are identical and they would overwrite each other. See README "Adopting an existing ACM certificate". Per-secret `acm-adopt-existing` annotation overrides this. |
| config.deleteBlocking | string | `"true"` | When `"true"` (default), finalizers are never force-removed on persistent delete failure — secret deletion blocks until the controller succeeds (Kubernetes-idiomatic finalizer behavior). When "false", the finalizer is force-removed after maxDeleteAttempts so a misconfigured store cannot wedge a secret; the remote certificate may then need manual cleanup. |
| config.deletePolicy | string | `"retain"` | Cluster-wide default for cleaning up remote certificates when a watched secret is deleted. "retain" (default) leaves remote state untouched. "delete" enables cleanup for every watched secret unless the per-secret delete-policy annotation opts back out. See README "Cleaning up remote certificates on secret deletion". |
| config.disableCache | string | `"false"` |  |
| config.disabledNamespaces | string | `""` |  |
| config.enabledNamespaces | string | `""` |  |
| config.logFormat | string | `"json"` |  |
| config.logLevel | string | `"info"` |  |
| config.maxDeleteAttempts | string | `"10"` | Maximum failed delete attempts before the operator gives up. `"0"` means retry forever. |
| config.operatorName | string | `"cert-manager-sync.lestak.sh"` |  |
| config.secretsNamespace | string | `""` |  |
| env | list | `[]` |  |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"robertlestak/cert-manager-sync"` |  |
| image.tag | string | `""` |  |
| imagePullSecrets | list | `[]` |  |
| leaderElection.createRole | bool | `true` | Create the namespaced `Role`/`RoleBinding` for the `Lease`. Set to `false` only if you manage that RBAC yourself — the operator needs `get`/`create`/`update` on `coordination.k8s.io` leases either way. |
| leaderElection.enabled | bool | `true` | Enable leader election. Required for `replicaCount` above 1. |
| leaderElection.leaseDuration | string | `"15s"` | How long a lease is honored before another replica may claim it. client-go requires `leaseDuration` > `renewDeadline` > `retryPeriod`; an inconsistent set is rejected at startup and the defaults are used instead. |
| leaderElection.lockName | string | `"cert-manager-sync-leader"` | Name of the `Lease` resource the replicas contend for. |
| leaderElection.namespace | string | `""` | Namespace holding the Lease. Defaults to the release namespace. If you point this elsewhere, that namespace needs its own Role for `coordination.k8s.io` leases — the chart only creates one in the release namespace. |
| leaderElection.renewDeadline | string | `"10s"` | How long the leader keeps trying to renew before giving up leadership. |
| leaderElection.required | string | `nil` | Refuse to start when leader election is enabled but the `Lease` RBAC is missing, instead of reconciling unelected. Defaults to on whenever `replicaCount` is above 1, where running unelected mints duplicate remote certificates. Leave unset to follow `replicaCount`. |
| leaderElection.retryPeriod | string | `"2s"` | How often candidates retry. |
| metrics.enabled | bool | `false` |  |
| metrics.port | int | `9090` |  |
| nameOverride | string | `""` |  |
| nodeSelector | object | `{}` |  |
| podAnnotations | object | `{}` |  |
| podDisruptionBudget.enabled | bool | `false` | Enable PodDisruptionBudget |
| podDisruptionBudget.maxUnavailable | string | `""` | Maximum number of pods that can be unavailable (alternative to minAvailable) |
| podDisruptionBudget.minAvailable | int | `1` | Minimum number of pods that must be available |
| podSecurityContext | object | `{}` |  |
| priorityClassName | string | `""` | Priority class name for pod scheduling |
| replicaCount | int | `1` |  |
| resources | object | `{}` |  |
| securityContext | object | `{}` |  |
| serviceAccount.annotations | object | `{}` |  |
| serviceAccount.create | bool | `true` |  |
| serviceAccount.name | string | `""` |  |
| tolerations | list | `[]` |  |
| topologySpreadConstraints | list | `[]` | Topology spread constraints for pod distribution |

