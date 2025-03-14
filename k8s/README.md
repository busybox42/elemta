# Elemta Kubernetes Deployment

This directory contains Kubernetes manifests for deploying Elemta in a Kubernetes cluster.

## Prerequisites

- Kubernetes cluster (v1.19+)
- kubectl configured to communicate with your cluster
- Docker Desktop with Kubernetes enabled (for local development)

## Files

- `deployment.yaml`: Defines the Elemta deployment
- `service.yaml`: Exposes the Elemta service
- `pvc.yaml`: Defines persistent volume claims for data storage
- `configmap.yaml`: Contains configuration for Elemta
- `secret.yaml`: Contains sensitive data like LDAP credentials
- `kustomization.yaml`: Ties all resources together for easy deployment

## Authentication Configuration

The deployment supports both SQLite and LDAP authentication:

### SQLite Authentication

SQLite authentication stores user credentials in a local database file. This is suitable for simple deployments or testing.

Configuration parameters:
- `AUTH_DATASOURCE_TYPE`: Set to "sqlite"
- `AUTH_SQLITE_PATH`: Path to the SQLite database file

### LDAP Authentication

LDAP authentication connects to an external LDAP server for user authentication. This is suitable for enterprise deployments.

Configuration parameters:
- `AUTH_DATASOURCE_TYPE`: Set to "ldap"
- `AUTH_LDAP_HOST`: LDAP server hostname
- `AUTH_LDAP_PORT`: LDAP server port (default: 389)
- `AUTH_LDAP_USER_DN`: Base DN for user searches
- `AUTH_LDAP_GROUP_DN`: Base DN for group searches
- `AUTH_LDAP_BIND_DN`: DN for binding to the LDAP server
- `AUTH_LDAP_BIND_PASSWORD`: Password for binding to the LDAP server

## Deployment

### Using kubectl

```bash
# Apply all resources
kubectl apply -k k8s/

# Or apply individual resources
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
```

### Using Docker Desktop Kubernetes

If you're using Docker Desktop with Kubernetes enabled:

1. Build the Docker image:
   ```bash
   docker build -t elemta:latest .
   ```

2. Apply the Kubernetes manifests:
   ```bash
   kubectl apply -k k8s/
   ```

3. Access the service:
   ```bash
   kubectl port-forward svc/elemta 2525:2525
   ```

## Customization

You can customize the deployment by editing the following files:

- `configmap.yaml`: Update the configuration values
- `secret.yaml`: Update the sensitive data (use a secure method in production)
- `deployment.yaml`: Adjust resource limits, replicas, etc.

## Production Considerations

For production deployments, consider the following:

1. Use a proper secret management solution (e.g., HashiCorp Vault, Kubernetes Secrets Store CSI Driver)
2. Set up proper resource limits and requests
3. Configure horizontal pod autoscaling
4. Use a proper ingress controller for TLS termination
5. Set up monitoring and logging
6. Use a proper CI/CD pipeline for deployments 