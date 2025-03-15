# Kubernetes Deployment for Elemta

This document provides instructions for deploying Elemta to a Kubernetes cluster.

## Prerequisites

- A Kubernetes cluster (minikube, kind, or a cloud provider)
- `kubectl` configured to use your cluster
- Docker images built (run `make docker-build` in the project root)

## Quick Start

### Deployment

To deploy Elemta to your Kubernetes cluster:

```bash
make k8s-deploy
```

This will create all necessary resources including:
- PersistentVolumeClaims for data storage
- ConfigMaps for configuration
- Deployment with the Elemta, ClamAV, and Rspamd containers
- Services to expose the components

### Testing

To test if the deployment is working correctly:

```bash
make k8s-test
```

### Cleanup

To remove the Kubernetes deployment:

```bash
make k8s-undeploy
```

## Architecture

The Kubernetes deployment includes:

- **Elemta SMTP Server**: The main email server component
- **ClamAV**: For virus scanning
- **Rspamd**: For spam filtering

All three components run in a single pod with shared volumes for configuration and data.

## Management Commands

- **Deploy**: `make k8s-deploy`
- **Undeploy**: `make k8s-undeploy`
- **Stop**: `make k8s-down`
- **Start**: `make k8s-up`
- **Restart**: `make k8s-restart`
- **View Logs**: `make k8s-logs`
- **Check Status**: `make k8s-status`
- **Run Tests**: `make k8s-test`

## Configuration

### Elemta Configuration

The Elemta server is configured via the `elemta-config` ConfigMap in the `elemta-all.yaml` file. Key settings include:

- SMTP server settings
- ClamAV integration
- Rspamd integration

For production, you should modify:
- `hostname`: Set to your actual mail server hostname
- `greeting`: Customize the SMTP greeting
- Authentication settings if needed

### Rspamd Configuration

Rspamd is configured via the `rspamd-config` ConfigMap. The configuration includes:

- Web interface settings (port 11334, exposed as NodePort 30334)
- Protocol interface settings (port 11333)
- No authentication for testing (add authentication for production)

### ClamAV Configuration

In this deployment, ClamAV runs as a container in the same pod as Elemta and Rspamd. It's accessible internally via the `elemta-clamav` service.

## Exposed Services

- **SMTP**: NodePort 30025 (mapped to port 25 in the container)
- **Rspamd Web Interface**: NodePort 30334 (mapped to port 11334 in the container)
- **ClamAV**: ClusterIP only (internal access via elemta-clamav:3310)

## Customization

### Using a Different Namespace

To deploy to a different namespace:

```bash
kubectl create namespace elemta
kubectl config set-context --current --namespace=elemta
make k8s-deploy
```

### Using Custom Images

To use custom images, modify the `elemta-all.yaml` file:

```yaml
containers:
- name: elemta
  image: your-registry/elemta:your-tag
```

### Resource Limits

For production deployments, consider adding resource limits:

```yaml
resources:
  limits:
    cpu: "1"
    memory: "1Gi"
  requests:
    cpu: "500m"
    memory: "512Mi"
```

## Troubleshooting

### Common Issues

1. **Pods not starting**: Check for resource constraints or image pull issues
   ```bash
   kubectl describe pod -l app=elemta
   ```

2. **Services not accessible**: Verify service and pod status
   ```bash
   kubectl get services
   kubectl get pods
   ```

3. **Configuration issues**: Check logs for configuration errors
   ```bash
   kubectl logs -l app=elemta -c elemta
   kubectl logs -l app=elemta -c rspamd
   kubectl logs -l app=elemta -c clamav
   ```

4. **Persistent volume issues**: Check PVC status
   ```bash
   kubectl get pvc
   ```

## Security Considerations

For production deployments:

1. **Enable TLS**: Configure TLS for SMTP and web interfaces
2. **Set resource limits**: Prevent resource exhaustion
3. **Use network policies**: Restrict pod communication
4. **Enable authentication**: Secure the Rspamd web interface
5. **Use secrets**: Store sensitive information in Kubernetes secrets 