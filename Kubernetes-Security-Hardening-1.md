Great! Let's now go **step-by-step** on **how to implement the same security layers on Kubernetes**:

> ✅ GOAL: Secure your **Kubernetes cluster, pods, application, and database** from:
>
> * Hackers & bots (like `dotneckbattle`)
> * Unauthorized access (read-only containers)
> * Prevent user copying files
> * Secure sessions in DB
> * Security checks at **Node, Pod, App, and DB level**

---

# 🛡️ LAYER 1: Cluster & Node Security

---

### 🔍 Problems:

* Anyone can access exposed Services (NodePort, LoadBalancer)
* SSH access to worker nodes is open
* You don’t know who changes the node, file, or container

---

### ✅ Solutions:

| Issue                 | Solution                                         |
| --------------------- | ------------------------------------------------ |
| Exposed ports         | Use **NetworkPolicies** + Ingress                |
| Node access           | Use **bastion host** with **read-only user**     |
| Monitor node activity | Install **auditd** or **Falco** on nodes         |
| Block file writing    | Use **readOnlyRootFilesystem: true** in Pod YAML |
| Restrict shell access | Avoid giving kubectl access to users directly    |

---

## 📦 Step-by-Step:

### 1.1 Restrict access with **NetworkPolicy** (deny all except needed):

```yaml
# deny all ingress by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: default
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

Apply:

```bash
kubectl apply -f deny-all.yaml
```

---

### 1.2 Monitor and log suspicious actions

Install [**Falco**](https://falco.org/):

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco --namespace falco --create-namespace
```

Falco watches:

* File access
* Shell exec
* Network activity in Pods

---

# 🐳 LAYER 2: Container Security

---

### 🔍 Problems:

* Users can write/change app code inside Pods
* User can copy files or run dangerous commands
* Hackers can get shell access and upload malware

---

### ✅ Solution:

Use **SecurityContext** + **readOnlyRootFilesystem** in your `Deployment` YAML.

---

## 📦 Step-by-step:

### 2.1 Sample secure Pod config

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsUser: 1001
        runAsNonRoot: true
      containers:
      - name: app
        image: yourrepo/secureapp:latest
        ports:
        - containerPort: 8000
        securityContext:
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir:
          medium: Memory
```

✅ Now this Pod:

* Can’t write to disk (`readOnlyRootFilesystem`)
* Can’t gain root or run privileged commands
* Has no capabilities like `NET_ADMIN`, `MKNOD`
* Can write **only** to `/tmp`

---

# 🌐 LAYER 3: Application Layer Security (rate-limiting, headers)

---

### 🔍 Problem:

* Bots like dotneckbattle can flood login endpoints.
* Weak session & CSRF protection

---

### ✅ Solutions:

| Issue             | Solution                                        |
| ----------------- | ----------------------------------------------- |
| Too many requests | Use **NGINX Ingress with rate limiting**        |
| Secure cookies    | App settings (e.g. Django)                      |
| Secure headers    | Use **nginx annotations**                       |
| CSRF/XSS          | Enable in application code (Django, Node, etc.) |

---

## 📦 Step-by-step:

### 3.1 Install **NGINX Ingress Controller** (if not installed)

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.9.4/deploy/static/provider/cloud/deploy.yaml
```

---

### 3.2 Add rate limiting in Ingress:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  annotations:
    nginx.ingress.kubernetes.io/limit-rps: "5"
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "3"
    nginx.ingress.kubernetes.io/proxy-body-size: "1m"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/x-forwarded-for-header: "X-Real-IP"
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: app-service
            port:
              number: 80
```

✅ This limits requests per IP to 5/sec with burst.

---

# 🛢️ LAYER 4: Database Security in Kubernetes

---

### 🔍 Problem:

* DB exposed to internet
* No session timeout
* Full access from app
* No SSL encryption

---

### ✅ Solution:

| Problem             | Fix                                 |
| ------------------- | ----------------------------------- |
| Public access       | Use **ClusterIP**, not NodePort     |
| No SSL              | Use **TLS** with PostgreSQL         |
| No session timeout  | Set timeouts in PostgreSQL          |
| Full DB access      | Use **read-only role**              |
| Multi-tenant access | Enable **RLS** (row-level security) |

---

## 📦 Step-by-step:

### 4.1 Deploy PostgreSQL securely (Helm):

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install pgdb bitnami/postgresql \
  --set auth.username=readonly \
  --set auth.password=securepass \
  --set auth.database=mydb \
  --set primary.resources.requests.memory=512Mi \
  --set primary.persistence.enabled=true
```

This creates PostgreSQL with a user: `readonly`

---

### 4.2 Set session expiry:

Login to DB:

```bash
kubectl exec -it pgdb-postgresql-0 -- psql -U postgres
```

Run:

```sql
ALTER ROLE readonly SET idle_in_transaction_session_timeout = '15min';
ALTER ROLE readonly SET statement_timeout = '10min';
```

---

### 4.3 Use read-only DB user in app secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-db-creds
type: Opaque
data:
  username: cmVhZG9ubHk=     # base64 of 'readonly'
  password: c2VjdXJlcGFzcw== # base64 of 'securepass'
```

---

# 🔍 LAYER 5: Monitoring & Daily Checks

---

| What to monitor   | Tool                                   |
| ----------------- | -------------------------------------- |
| Security events   | Falco                                  |
| File changes      | auditd or OPA Gatekeeper               |
| Vulnerable images | Trivy in CI                            |
| Open ports        | Kubernetes NetworkPolicy               |
| API usage         | Audit logs (enabled in EKS, AKS, etc.) |

---

# 🧠 Summary

| Layer          | Action                                    |
| -------------- | ----------------------------------------- |
| **Cluster**    | NetworkPolicy, Falco, RBAC                |
| **Node**       | No SSH, read-only file system             |
| **Pod**        | Drop capabilities, readOnlyRootFilesystem |
| **App**        | Ingress rate limit, secure cookies        |
| **DB**         | Read-only user, session timeout           |
| **Monitoring** | Falco, auditd, trivy, Prometheus          |

---

Would you like a full Helm or `kubectl` script to auto-deploy this setup? Let me know and I’ll generate it for you.
