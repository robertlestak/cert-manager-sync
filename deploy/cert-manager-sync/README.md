# cert-manager-sync

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 1.0.0](https://img.shields.io/badge/AppVersion-1.0.0-informational?style=flat-square)

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
| config.disableCache | string | `"false"` |  |
| config.disabledNamespaces | string | `""` |  |
| config.enabledNamespaces | string | `""` |  |
| config.logFormat | string | `"json"` |  |
| config.logLevel | string | `"info"` |  |
| config.operatorName | string | `"cert-manager-sync.lestak.sh"` |  |
| config.secretsNamespace | string | `""` |  |
| env | list | `[]` |  |
| fullnameOverride | string | `""` |  |
| image.pullPolicy | string | `"IfNotPresent"` |  |
| image.repository | string | `"robertlestak/cert-manager-sync"` |  |
| image.tag | string | `"latest"` |  |
| imagePullSecrets | list | `[]` |  |
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

