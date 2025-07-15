# Kubernetes Security Hardening Guide

This comprehensive guide covers securing Kubernetes clusters against hackers, bots, DoS attacks, and implementing read-only access controls with session management.

## Table of Contents
1. [Cluster-Level Security](#cluster-level-security)
2. [Node-Level Security](#node-level-security)
3. [Workload Security](#workload-security)
4. [Network Security](#network-security)
5. [Read-Only Access Implementation](#read-only-access-kubernetes)
6. [Preventing Data Exfiltration](#preventing-data-exfiltration)
7. [Session Management](#session-management-kubernetes)
8. [DDoS/DoS Protection](#ddos-protection-kubernetes)
9. [Monitoring & Auditing](#monitoring-auditing)

## Cluster-Level Security

### 1. Secure API Server
```bash
# Edit API server manifest
sudo nano /etc/kubernetes/manifests/kube-apiserver.yaml

# Add/Modify these flags:
- --anonymous-auth=false
- --enable-admission-plugins=NodeRestriction,PodSecurityPolicy
- --disable-admission-plugins=AlwaysAdmit
- --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- --authorization-mode=Node,RBAC
- --audit-log-path=/var/log/apiserver/audit.log
- --audit-log-maxage=30
- --audit-log-maxbackup=10
- --audit-log-maxsize=100
```

### 2. Enable RBAC
```bash
# Verify RBAC is enabled
kubectl api-versions | grep rbac.authorization.k8s.io

# Create role for read-only access
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
EOF
```

### 3. Pod Security Policies (PSP)
```bash
# Create a restrictive PSP
kubectl apply -f - <<EOF
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      - min: 1
        max: 65535
  readOnlyRootFilesystem: true
EOF
```

## Node-Level Security

### 1. Secure Kubelet
```bash
# On each worker node, edit kubelet config
sudo nano /var/lib/kubelet/config.yaml

# Add/Modify:
authentication:
  anonymous:
    enabled: false
  webhook:
    enabled: true
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
```

### 2. Node Hardening
```bash
# Apply kernel hardening
echo "kernel.modules_disabled=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians=1" | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Install and configure fail2ban
sudo apt install fail2ban
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Add Kubernetes protection
sudo nano /etc/fail2ban/jail.local
```
Add to the file:
```
[kubernetes-api]
enabled  = true
port     = 6443,8443
filter   = kubernetes-api
logpath  = /var/log/kubernetes/audit.log
maxretry = 3
bantime  = 3600
```

## Workload Security

### 1. Pod Security Context
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secured-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: secured-image:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
      privileged: false
```

### 2. Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## Network Security

### 1. Ingress Controller Security
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/limit-connections: "100"
    nginx.ingress.kubernetes.io/limit-rps: "100"
spec:
  tls:
  - hosts:
    - yourdomain.com
    secretName: tls-secret
  rules:
  - host: yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: web-service
            port:
              number: 80
```

### 2. Service Mesh (Istio) Security
```bash
# Install Istio with security features
istioctl install --set profile=demo --set values.global.mtls.enabled=true

# Enable mTLS for services
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
spec:
  mtls:
    mode: STRICT
EOF
```

## Read-Only Access in Kubernetes

### 1. Create Read-Only User
```bash
# Create certificate for user
openssl genrsa -out readonly.key 2048
openssl req -new -key readonly.key -out readonly.csr -subj "/CN=readonly/O=readonly-group"
openssl x509 -req -in readonly.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out readonly.crt -days 365

# Create kubeconfig
kubectl config set-credentials readonly --client-certificate=readonly.crt --client-key=readonly.key --embed-certs=true
kubectl config set-context readonly-context --cluster=kubernetes --user=readonly
kubectl config use-context readonly-context

# Create Role and RoleBinding
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
  name: readonly-role
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  namespace: default
  name: readonly-binding
subjects:
- kind: User
  name: readonly
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: readonly-role
  apiGroup: rbac.authorization.k8s.io
EOF
```

### 2. Read-Only Access to Docker Images
```bash
# Use imagePullSecrets with read-only registry credentials
kubectl create secret docker-registry readonly-registry \
  --docker-server=your.registry.io \
  --docker-username=readonly \
  --docker-password=yourpassword
```

## Preventing Data Exfiltration

### 1. Network Policies to Block External Access
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-external-egress
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: TCP
      port: 53
    - protocol: UDP
      port: 53
```

### 2. Disable Kubectl Copy
```bash
# Create custom role without exec/create permissions
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: restricted-user
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
EOF
```

## Session Management in Kubernetes

### 1. Database Session Timeout
```yaml
# Example deployment with connection limits
apiVersion: apps/v1
kind: Deployment
metadata:
  name: db-app
spec:
  template:
    spec:
      containers:
      - name: db
        image: mysql:5.7
        env:
        - name: MYSQL_DEFAULT_WAIT_TIMEOUT
          value: "1800"  # 30 minutes
        - name: MYSQL_INTERACTIVE_TIMEOUT
          value: "1800"
```

### 2. Application Session Management
```yaml
# Example deployment with session timeout
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
spec:
  template:
    spec:
      containers:
      - name: web
        image: your-web-app:latest
        env:
        - name: SESSION_TIMEOUT
          value: "1800"  # 30 minutes
        - name: SESSION_COOKIE_SECURE
          value: "true"
        - name: SESSION_COOKIE_HTTPONLY
          value: "true"
```

## DDoS Protection in Kubernetes

### 1. Rate Limiting with Nginx Ingress
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rate-limited-ingress
  annotations:
    nginx.ingress.kubernetes.io/limit-connections: "100"
    nginx.ingress.kubernetes.io/limit-rps: "100"
    nginx.ingress.kubernetes.io/limit-burst: "50"
    nginx.ingress.kubernetes.io/deny-ips: "1.2.3.4,5.6.7.8" # Bad IPs
```

### 2. Horizontal Pod Autoscaler
```yaml
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: app-autoscaler
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: your-app
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Monitoring & Auditing

### 1. Enable Kubernetes Auditing
```bash
# Create audit policy
sudo nano /etc/kubernetes/audit-policy.yaml
```
```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["kube-system"]
- level: RequestResponse
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
- level: Request
  resources:
  - group: ""
    resources: ["pods", "services"]
```

### 2. Install Falco for Runtime Security
```bash
# Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco

# Custom rules for detecting data exfiltration
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: falco-rules
data:
  local_rules.yaml: |
    - rule: Unexpected outbound network connection
      desc: Detect outbound connections not to known services
      condition: >
        outbound and
        not (fd.sip in (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)) and
        not (fd.sport in (53, 80, 443))
      output: Unexpected outbound network connection (command=%proc.cmdline connection=%fd.name)
      priority: WARNING
EOF
```

### 3. Kubernetes Dashboard with RBAC
```bash
# Install dashboard with restricted access
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml

# Create read-only user for dashboard
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: dashboard-readonly
  namespace: kubernetes-dashboard
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: dashboard-readonly
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: view
subjects:
- kind: ServiceAccount
  name: dashboard-readonly
  namespace: kubernetes-dashboard
EOF
```

## Continuous Security Practices

1. **Regular Updates**: Keep Kubernetes and all components updated
   ```bash
   kubectl get nodes -o wide
   kubectl upgrade...
   ```

2. **Image Scanning**: Use tools like Trivy or Clair
   ```bash
   trivy image your-image:tag
   ```

3. **Configuration Scanning**: Use kube-bench
   ```bash
   kubectl apply -f job.yaml
   ```

4. **Network Policy Testing**: Use tools like Network Policy Validator

5. **Secret Management**: Use sealed-secrets or external vaults
   ```bash
   kubectl create secret generic db-secret --from-literal=password='S!B\*d$zDsb='
   ```

This comprehensive Kubernetes security implementation provides defense in depth against various threats while maintaining operational flexibility. Regularly review and update your security configurations as new threats emerge and Kubernetes evolves.
