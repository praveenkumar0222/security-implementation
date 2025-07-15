Great — let’s explain everything **clearly, one-by-one**, step-by-step, with commands and real understanding.

---

## ✅ GOAL:

You want to **secure your server, application, and database** from:

* 🦠 Hackers and bots (like **dotneckbattle**, brute-force, DoS attacks)
* 📦 Unauthorized access (like user copying files or seeing Docker container code)
* 🔐 Give users **read-only** access (even inside Docker)
* ⏳ Expire user sessions in database
* ✅ Implement **security checks** for server, application, and DB

---

# 🔒 STEP 1: Server Level Security

### 🔍 What issues can happen?

* Anyone can access your server on any open port.
* Brute-force login attempts (password guessing).
* If a user logs in, they might copy your code or files.
* If someone uploads malware or makes config changes, you won’t even know.

---

### ✅ Solution:

| Protection                | Tool                      | What it does                 |
| ------------------------- | ------------------------- | ---------------------------- |
| Block unnecessary ports   | `ufw` (firewall)          | Block all except SSH & HTTPS |
| Block brute-force         | `fail2ban`                | Auto-ban IPs attacking SSH   |
| Prevent file modification | Read-only directories     | Stop writing changes         |
| Audit file changes        | `auditd`                  | Log if someone changes files |
| Stop copying files        | Restrict shell, SCP, SFTP | Prevent file downloads       |

---

### 🛠️ Step-by-step Implementation

#### 1.1 🧱 Enable basic firewall

```bash
sudo apt update
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw allow 22/tcp     # SSH
sudo ufw allow 443/tcp    # HTTPS
sudo ufw enable
```

---

#### 1.2 🔐 Install and configure fail2ban

```bash
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

Basic protection for SSH is enabled by default.

---

#### 1.3 🕵️ Setup audit logging

```bash
sudo apt install auditd
sudo auditctl -w /srv/app -p war -k app_watch
```

* Logs if someone **writes**, **reads**, or **changes** `/srv/app` folder.

---

#### 1.4 👀 Create read-only user on server

```bash
sudo useradd -m -s /bin/rbash roviewer
sudo passwd roviewer
sudo chmod 555 /home/roviewer
```

👉 `rbash` = restricted shell
👉 No write permission = read-only files

---

#### 1.5 ❌ Block file copying (SCP, SFTP)

Edit SSH config:

```bash
sudo nano /etc/ssh/sshd_config
```

Add at the end:

```
Match User roviewer
    AllowTcpForwarding no
    PermitTunnel no
    X11Forwarding no
    ForceCommand /usr/bin/less
```

Then:

```bash
sudo systemctl restart sshd
```

🧠 This allows reading files (e.g., `less app.py`) but blocks copying, uploading, etc.

---

# 🐳 STEP 2: Docker Container Read-Only

### 🚨 Problem:

If user enters Docker container, they may change code, download files, install malware, etc.

---

### ✅ Solution:

Run Docker containers in **read-only** mode with **dropped capabilities**.

---

### 🛠️ Commands:

```bash
docker run \
  --read-only \
  --cap-drop ALL \
  --tmpfs /tmp \
  --user 1001:1001 \
  -p 8080:80 \
  myapp:latest
```

✅ Explanation:

| Option           | What it does                           |
| ---------------- | -------------------------------------- |
| `--read-only`    | Root filesystem is read-only           |
| `--cap-drop ALL` | Disable container’s admin powers       |
| `--tmpfs /tmp`   | Create a temporary writable `/tmp` dir |
| `--user`         | Runs as non-root user                  |

Now, even if user enters the container:

* ❌ Can’t edit code
* ❌ Can’t write to disk
* ❌ Can’t copy code

---

# 🌐 STEP 3: Application Level Security

### 🔥 Problems:

* App receives too many login requests (DoS).
* CSRF, XSS, Insecure cookies.
* Auth/session not secure.

---

### ✅ Solutions:

| Problem                 | Fix                        |
| ----------------------- | -------------------------- |
| Too many login requests | Rate limit using NGINX     |
| Secure cookies          | Use Django secure settings |
| CSRF/XSS protection     | Use headers & middleware   |
| Session timeout         | Set cookie timeout in app  |

---

### 🛠️ Commands / Configuration

#### 3.1 ⏱ Rate limit in NGINX

Edit `/etc/nginx/conf.d/ratelimit.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=req_limit_per_ip:10m rate=10r/s;

server {
    location / {
        limit_req zone=req_limit_per_ip burst=20;
        proxy_pass http://app:8000;
    }
}
```

Restart nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

---

#### 3.2 ⚙️ Django Security Settings (example)

In `settings.py`:

```python
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True

# Session expires in 30 min
SESSION_COOKIE_AGE = 1800
```

---

# 🛢️ STEP 4: Database Level Security (PostgreSQL)

### 🎯 Problems:

* Open access to DB from outside.
* Session never expires.
* Users have full permissions (DROP, DELETE, etc.).
* Data theft or leak.

---

### ✅ Solutions:

| What to do                       | Why                               |
| -------------------------------- | --------------------------------- |
| Set password encryption to SCRAM | Avoid weak MD5 passwords          |
| Enable SSL                       | Prevent plain text auth           |
| Use separate read-only DB roles  | Limit what user can do            |
| Set session timeout              | Auto logout                       |
| Enable RLS (row-level security)  | Limit data access per tenant/user |

---

### 🛠️ Step-by-step Setup

#### 4.1 🔐 Enable password encryption and SSL

Edit `postgresql.conf`:

```conf
ssl = on
password_encryption = scram-sha-256
```

Restart:

```bash
sudo systemctl restart postgresql
```

---

#### 4.2 👤 Create read-only database user

```sql
-- Login as postgres
CREATE ROLE readonly_user WITH LOGIN PASSWORD 'StrongPass123';
GRANT CONNECT ON DATABASE mydb TO readonly_user;
\c mydb
GRANT USAGE ON SCHEMA public TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
```

🧠 This user can only **read data**.

---

#### 4.3 🕒 Set session timeout

```sql
ALTER ROLE readonly_user SET idle_in_transaction_session_timeout = '15min';
ALTER SYSTEM SET statement_timeout = '10min';
SELECT pg_reload_conf();
```

📌 This ensures idle sessions are **auto-closed**.

---

# ✅ Final Checklist: Security Checks

| Area                     | What to check     | Tools                     |
| ------------------------ | ----------------- | ------------------------- |
| Server ports             | Only 22, 443 open | `ufw`, `nmap`             |
| SSH brute-force          | IP banned         | `fail2ban`                |
| Unauthorized file access | Logs shown        | `auditd`                  |
| Code tampering           | Blocked           | read-only Docker, user    |
| App spam/flood           | Blocked           | nginx rate-limiting       |
| DB session control       | Timed out         | PostgreSQL timeout        |
| DB access                | Only SELECT       | PostgreSQL read-only user |

---

## 🎉 Summary

| Layer      | What you did                                |
| ---------- | ------------------------------------------- |
| **Server** | Firewall, audit logs, read-only user        |
| **Docker** | Run container read-only with no privileges  |
| **App**    | Rate-limit, secure cookies, session timeout |
| **DB**     | Read-only user, session timeout, encryption |

---

If you'd like, I can generate a script or playbook to automate all this. Just let me know.
