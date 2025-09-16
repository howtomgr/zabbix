# Zabbix Installation Guide

Zabbix is a free and open-source Monitoring Platform. An enterprise-class monitoring solution for networks and applications

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 10GB minimum
  - Network: 80 ports required
- **Operating System**: 
  - Linux: Any modern distribution (RHEL, Debian, Ubuntu, CentOS, Fedora, Arch, Alpine, openSUSE)
  - macOS: 10.14+ (Mojave or newer)
  - Windows: Windows Server 2016+ or Windows 10 Pro
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 80 (default zabbix port)
  - Firewall rules configured
- **Dependencies**:
  - mysql, php, apache, zabbix-agent
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository if needed
sudo dnf install -y epel-release

# Install zabbix
sudo dnf install -y zabbix mysql, php, apache, zabbix-agent

# Enable and start service
sudo systemctl enable --now zabbix-server

# Configure firewall
sudo firewall-cmd --permanent --add-service=zabbix || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
zabbix --version || systemctl status zabbix-server
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install zabbix
sudo apt install -y zabbix mysql, php, apache, zabbix-agent

# Enable and start service
sudo systemctl enable --now zabbix-server

# Configure firewall
sudo ufw allow 80

# Verify installation
zabbix --version || systemctl status zabbix-server
```

### Arch Linux

```bash
# Install zabbix
sudo pacman -S zabbix

# Enable and start service
sudo systemctl enable --now zabbix-server

# Verify installation
zabbix --version || systemctl status zabbix-server
```

### Alpine Linux

```bash
# Install zabbix
apk add --no-cache zabbix

# Enable and start service
rc-update add zabbix-server default
rc-service zabbix-server start

# Verify installation
zabbix --version || rc-service zabbix-server status
```

### openSUSE/SLES

```bash
# Install zabbix
sudo zypper install -y zabbix mysql, php, apache, zabbix-agent

# Enable and start service
sudo systemctl enable --now zabbix-server

# Configure firewall
sudo firewall-cmd --permanent --add-service=zabbix || \
  sudo firewall-cmd --permanent --add-port={default_port}/tcp
sudo firewall-cmd --reload

# Verify installation
zabbix --version || systemctl status zabbix-server
```

### macOS

```bash
# Using Homebrew
brew install zabbix

# Start service
brew services start zabbix

# Verify installation
zabbix --version
```

### FreeBSD

```bash
# Using pkg
pkg install zabbix

# Enable in rc.conf
echo 'zabbix-server_enable="YES"' >> /etc/rc.conf

# Start service
service zabbix-server start

# Verify installation
zabbix --version || service zabbix-server status
```

### Windows

```powershell
# Using Chocolatey
choco install zabbix

# Or using Scoop
scoop install zabbix

# Verify installation
zabbix --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create configuration directory if needed
sudo mkdir -p /etc/zabbix

# Set up basic configuration
sudo tee /etc/zabbix/zabbix.conf << 'EOF'
# Zabbix Configuration
CacheSize=32M, StartPollers=5
EOF

# Set appropriate permissions
sudo chown -R zabbix:zabbix /etc/zabbix || \
  sudo chown -R $(whoami):$(whoami) /etc/zabbix

# Test configuration
sudo zabbix --test || sudo zabbix-server configtest
```

### Security Hardening

```bash
# Create dedicated user (if not created by package)
sudo useradd --system --shell /bin/false zabbix || true

# Secure configuration files
sudo chmod 750 /etc/zabbix
sudo chmod 640 /etc/zabbix/*.conf

# Enable security features
# See security section for detailed hardening steps
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable zabbix-server

# Start service
sudo systemctl start zabbix-server

# Stop service
sudo systemctl stop zabbix-server

# Restart service
sudo systemctl restart zabbix-server

# Reload configuration
sudo systemctl reload zabbix-server

# Check status
sudo systemctl status zabbix-server

# View logs
sudo journalctl -u zabbix-server -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add zabbix-server default

# Start service
rc-service zabbix-server start

# Stop service
rc-service zabbix-server stop

# Restart service
rc-service zabbix-server restart

# Check status
rc-service zabbix-server status

# View logs
tail -f /var/log/zabbix/zabbix-server.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'zabbix-server_enable="YES"' >> /etc/rc.conf

# Start service
service zabbix-server start

# Stop service
service zabbix-server stop

# Restart service
service zabbix-server restart

# Check status
service zabbix-server status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start zabbix
brew services stop zabbix
brew services restart zabbix

# Check status
brew services list | grep zabbix

# View logs
tail -f $(brew --prefix)/var/log/zabbix.log
```

### Windows Service Manager

```powershell
# Start service
net start zabbix-server

# Stop service
net stop zabbix-server

# Using PowerShell
Start-Service zabbix-server
Stop-Service zabbix-server
Restart-Service zabbix-server

# Check status
Get-Service zabbix-server

# Set to automatic startup
Set-Service zabbix-server -StartupType Automatic
```

## Advanced Configuration

### Performance Optimization

```bash
# Configure performance settings
cat >> /etc/zabbix/zabbix.conf << 'EOF'
# Performance tuning
CacheSize=32M, StartPollers=5
EOF

# Apply system tuning
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Restart service to apply changes
sudo systemctl restart zabbix-server
```

### High Availability Setup

```bash
# Configure clustering/HA (if supported)
# This varies greatly by tool - see official documentation

# Example load balancing configuration
# Configure multiple instances on different ports
# Use HAProxy or nginx for load balancing
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
upstream zabbix_backend {
    server 127.0.0.1:80;
    keepalive 32;
}

server {
    listen 80;
    server_name zabbix.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name zabbix.example.com;

    ssl_certificate /etc/ssl/certs/zabbix.crt;
    ssl_certificate_key /etc/ssl/private/zabbix.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://zabbix_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:80>
    ServerName zabbix.example.com
    Redirect permanent / https://zabbix.example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName zabbix.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/zabbix.crt
    SSLCertificateKeyFile /etc/ssl/private/zabbix.key
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options SAMEORIGIN
    Header always set X-XSS-Protection "1; mode=block"
    
    ProxyRequests Off
    ProxyPreserveHost On
    
    <Location />
        ProxyPass http://127.0.0.1:80/
        ProxyPassReverse http://127.0.0.1:80/
    </Location>
    
    # WebSocket support (if needed)
    RewriteEngine on
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://127.0.0.1:80/$1" [P,L]
</VirtualHost>
```

### HAProxy Configuration

```haproxy
global
    maxconn 4096
    log /dev/log local0
    chroot /var/lib/haproxy
    user haproxy
    group haproxy
    daemon

defaults
    log global
    mode http
    option httplog
    option dontlognull
    timeout connect 5000
    timeout client 50000
    timeout server 50000

frontend zabbix_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/zabbix.pem
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-XSS-Protection "1; mode=block"
    
    default_backend zabbix_backend

backend zabbix_backend
    balance roundrobin
    option httpchk GET /health
    server zabbix1 127.0.0.1:80 check
```

### Caddy Configuration

```caddy
zabbix.example.com {
    reverse_proxy 127.0.0.1:80 {
        header_up Host {upstream_hostport}
        header_up X-Real-IP {remote}
        header_up X-Forwarded-For {remote}
        header_up X-Forwarded-Proto {scheme}
    }
    
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options nosniff
        X-Frame-Options SAMEORIGIN
        X-XSS-Protection "1; mode=block"
    }
    
    encode gzip
}
```

## Security Configuration

### Basic Security Setup

```bash
# Create dedicated user
sudo useradd --system --shell /bin/false --home /etc/zabbix zabbix || true

# Set ownership
sudo chown -R zabbix:zabbix /etc/zabbix
sudo chown -R zabbix:zabbix /var/log/zabbix

# Set permissions
sudo chmod 750 /etc/zabbix
sudo chmod 640 /etc/zabbix/*
sudo chmod 750 /var/log/zabbix

# Configure firewall (UFW)
sudo ufw allow from any to any port 80 proto tcp comment "Zabbix"

# Configure firewall (firewalld)
sudo firewall-cmd --permanent --new-service=zabbix
sudo firewall-cmd --permanent --service=zabbix --add-port={default_port}/tcp
sudo firewall-cmd --permanent --add-service=zabbix
sudo firewall-cmd --reload

# SELinux configuration (if enabled)
sudo setsebool -P httpd_can_network_connect on
sudo semanage port -a -t http_port_t -p tcp 80 || true
```

### SSL/TLS Configuration

```bash
# Generate self-signed certificate (for testing)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/zabbix.key \
    -out /etc/ssl/certs/zabbix.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=zabbix.example.com"

# Set proper permissions
sudo chmod 600 /etc/ssl/private/zabbix.key
sudo chmod 644 /etc/ssl/certs/zabbix.crt

# For production, use Let's Encrypt
sudo certbot certonly --standalone -d zabbix.example.com
```

### Fail2ban Configuration

```ini
# /etc/fail2ban/jail.d/zabbix.conf
[zabbix]
enabled = true
port = 80
filter = zabbix
logpath = /var/log/zabbix/*.log
maxretry = 5
bantime = 3600
findtime = 600
```

```ini
# /etc/fail2ban/filter.d/zabbix.conf
[Definition]
failregex = ^.*Failed login attempt.*from <HOST>.*$
            ^.*Authentication failed.*from <HOST>.*$
            ^.*Invalid credentials.*from <HOST>.*$
ignoreregex =
```

## Database Setup

### PostgreSQL Backend (if applicable)

```bash
# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE zabbix_db;
CREATE USER zabbix_user WITH ENCRYPTED PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE zabbix_db TO zabbix_user;
\q
EOF

# Configure connection in Zabbix
echo "DATABASE_URL=postgresql://zabbix_user:secure_password_here@localhost/zabbix_db" | \
  sudo tee -a /etc/zabbix/zabbix.env
```

### MySQL/MariaDB Backend (if applicable)

```bash
# Create database and user
sudo mysql << EOF
CREATE DATABASE zabbix_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'zabbix_user'@'localhost' IDENTIFIED BY 'secure_password_here';
GRANT ALL PRIVILEGES ON zabbix_db.* TO 'zabbix_user'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure connection
echo "DATABASE_URL=mysql://zabbix_user:secure_password_here@localhost/zabbix_db" | \
  sudo tee -a /etc/zabbix/zabbix.env
```

### SQLite Backend (if applicable)

```bash
# Create database directory
sudo mkdir -p /var/lib/zabbix
sudo chown zabbix:zabbix /var/lib/zabbix

# Initialize database
sudo -u zabbix zabbix init-db
```

## Performance Optimization

### System Tuning

```bash
# Kernel parameters for better performance
cat << 'EOF' | sudo tee -a /etc/sysctl.conf
# Network performance tuning
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_tw_reuse = 1

# Memory tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply settings
sudo sysctl -p

# Configure system limits
cat << 'EOF' | sudo tee -a /etc/security/limits.conf
zabbix soft nofile 65535
zabbix hard nofile 65535
zabbix soft nproc 32768
zabbix hard nproc 32768
EOF
```

### Application Tuning

```bash
# Configure application-specific performance settings
cat << 'EOF' | sudo tee -a /etc/zabbix/performance.conf
# Performance configuration
CacheSize=32M, StartPollers=5

# Connection pooling
max_connections = 1000
connection_timeout = 30

# Cache settings
cache_size = 256M
cache_ttl = 3600

# Worker processes
workers = 4
threads_per_worker = 4
EOF

# Restart to apply settings
sudo systemctl restart zabbix-server
```

## Monitoring

### Prometheus Integration

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'zabbix'
    static_configs:
      - targets: ['localhost:80/metrics']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

### Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/zabbix-health

# Check if service is running
if ! systemctl is-active --quiet zabbix-server; then
    echo "CRITICAL: Zabbix service is not running"
    exit 2
fi

# Check if port is listening
if ! nc -z localhost 80 2>/dev/null; then
    echo "CRITICAL: Zabbix is not listening on port 80"
    exit 2
fi

# Check response time
response_time=$(curl -o /dev/null -s -w '%{time_total}' http://localhost:80/health || echo "999")
if (( $(echo "$response_time > 5" | bc -l) )); then
    echo "WARNING: Slow response time: ${response_time}s"
    exit 1
fi

echo "OK: Zabbix is healthy (response time: ${response_time}s)"
exit 0
```

### Log Monitoring

```bash
# Configure log rotation
cat << 'EOF' | sudo tee /etc/logrotate.d/zabbix
/var/log/zabbix/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 zabbix zabbix
    postrotate
        systemctl reload zabbix-server > /dev/null 2>&1 || true
    endscript
}
EOF

# Test log rotation
sudo logrotate -d /etc/logrotate.d/zabbix
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# /usr/local/bin/zabbix-backup

BACKUP_DIR="/backup/zabbix"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/zabbix_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop service (if needed for consistency)
echo "Stopping Zabbix service..."
systemctl stop zabbix-server

# Backup configuration
echo "Backing up configuration..."
tar -czf "$BACKUP_FILE" \
    /etc/zabbix \
    /var/lib/zabbix \
    /var/log/zabbix

# Backup database (if applicable)
if command -v pg_dump &> /dev/null; then
    echo "Backing up database..."
    sudo -u postgres pg_dump zabbix_db | gzip > "$BACKUP_DIR/zabbix_db_$DATE.sql.gz"
fi

# Start service
echo "Starting Zabbix service..."
systemctl start zabbix-server

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +30 -delete
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Restore Script

```bash
#!/bin/bash
# /usr/local/bin/zabbix-restore

if [ $# -ne 1 ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop service
echo "Stopping Zabbix service..."
systemctl stop zabbix-server

# Restore files
echo "Restoring from backup..."
tar -xzf "$BACKUP_FILE" -C /

# Restore database (if applicable)
DB_BACKUP=$(echo "$BACKUP_FILE" | sed 's/.tar.gz$/_db.sql.gz/')
if [ -f "$DB_BACKUP" ]; then
    echo "Restoring database..."
    zcat "$DB_BACKUP" | sudo -u postgres psql zabbix_db
fi

# Fix permissions
chown -R zabbix:zabbix /etc/zabbix
chown -R zabbix:zabbix /var/lib/zabbix

# Start service
echo "Starting Zabbix service..."
systemctl start zabbix-server

echo "Restore completed successfully"
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check service status and logs
sudo systemctl status zabbix-server
sudo journalctl -u zabbix-server -n 100 --no-pager

# Check for port conflicts
sudo ss -tlnp | grep 80
sudo lsof -i :80

# Verify configuration
sudo zabbix --test || sudo zabbix-server configtest

# Check permissions
ls -la /etc/zabbix
ls -la /var/log/zabbix
```

2. **Cannot access web interface**:
```bash
# Check if service is listening
sudo ss -tlnp | grep zabbix-server
curl -I http://localhost:80

# Check firewall rules
sudo firewall-cmd --list-all
sudo iptables -L -n | grep 80

# Check SELinux (if enabled)
getenforce
sudo ausearch -m avc -ts recent | grep zabbix
```

3. **High memory/CPU usage**:
```bash
# Monitor resource usage
top -p $(pgrep zabbix_server)
htop -p $(pgrep zabbix_server)

# Check for memory leaks
ps aux | grep zabbix_server
cat /proc/$(pgrep zabbix_server)/status | grep -i vm

# Analyze logs for errors
grep -i error /var/log/zabbix/*.log | tail -50
```

4. **Database connection errors**:
```bash
# Test database connection
psql -U zabbix_user -d zabbix_db -c "SELECT 1;"
mysql -u zabbix_user -p zabbix_db -e "SELECT 1;"

# Check database service
sudo systemctl status postgresql
sudo systemctl status mariadb
```

### Debug Mode

```bash
# Enable debug logging
echo "debug = true" | sudo tee -a /etc/zabbix/zabbix.conf

# Restart with debug mode
sudo systemctl stop zabbix-server
sudo -u zabbix zabbix --debug

# Watch debug logs
tail -f /var/log/zabbix/debug.log
```

### Performance Analysis

```bash
# Profile CPU usage
sudo perf record -p $(pgrep zabbix_server) sleep 30
sudo perf report

# Analyze network traffic
sudo tcpdump -i any -w /tmp/zabbix.pcap port 80
sudo tcpdump -r /tmp/zabbix.pcap -nn

# Monitor disk I/O
sudo iotop -p $(pgrep zabbix_server)
```

## Integration Examples

### Docker Deployment

```yaml
# docker-compose.yml
version: '3.8'

services:
  zabbix:
    image: zabbix:zabbix
    container_name: zabbix
    restart: unless-stopped
    ports:
      - "80:80"
    environment:
      - TZ=UTC
      - PUID=1000
      - PGID=1000
    volumes:
      - ./config:/etc/zabbix
      - ./data:/var/lib/zabbix
      - ./logs:/var/log/zabbix
    networks:
      - zabbix_network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/health"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  zabbix_network:
    driver: bridge
```

### Kubernetes Deployment

```yaml
# zabbix-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zabbix
  labels:
    app: zabbix
spec:
  replicas: 1
  selector:
    matchLabels:
      app: zabbix
  template:
    metadata:
      labels:
        app: zabbix
    spec:
      containers:
      - name: zabbix
        image: zabbix:zabbix
        ports:
        - containerPort: 80
        env:
        - name: TZ
          value: UTC
        volumeMounts:
        - name: config
          mountPath: /etc/zabbix
        - name: data
          mountPath: /var/lib/zabbix
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config
        configMap:
          name: zabbix-config
      - name: data
        persistentVolumeClaim:
          claimName: zabbix-data
---
apiVersion: v1
kind: Service
metadata:
  name: zabbix
spec:
  selector:
    app: zabbix
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  type: LoadBalancer
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: zabbix-data
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

### Ansible Playbook

```yaml
---
# zabbix-playbook.yml
- name: Install and configure Zabbix
  hosts: all
  become: yes
  vars:
    zabbix_version: latest
    zabbix_port: 80
    zabbix_config_dir: /etc/zabbix
  
  tasks:
    - name: Install dependencies
      package:
        name:
          - mysql, php, apache, zabbix-agent
        state: present
    
    - name: Install Zabbix
      package:
        name: zabbix
        state: present
    
    - name: Create configuration directory
      file:
        path: "{{ zabbix_config_dir }}"
        state: directory
        owner: zabbix
        group: zabbix
        mode: '0750'
    
    - name: Deploy configuration
      template:
        src: zabbix.conf.j2
        dest: "{{ zabbix_config_dir }}/zabbix.conf"
        owner: zabbix
        group: zabbix
        mode: '0640'
      notify: restart zabbix
    
    - name: Start and enable service
      systemd:
        name: zabbix-server
        state: started
        enabled: yes
        daemon_reload: yes
    
    - name: Configure firewall
      firewalld:
        port: "{{ zabbix_port }}/tcp"
        permanent: yes
        immediate: yes
        state: enabled
  
  handlers:
    - name: restart zabbix
      systemd:
        name: zabbix-server
        state: restarted
```

### Terraform Configuration

```hcl
# zabbix.tf
resource "aws_instance" "zabbix_server" {
  ami           = var.ami_id
  instance_type = "t3.medium"
  
  vpc_security_group_ids = [aws_security_group.zabbix.id]
  
  user_data = <<-EOF
    #!/bin/bash
    # Install Zabbix
    apt-get update
    apt-get install -y zabbix mysql, php, apache, zabbix-agent
    
    # Configure Zabbix
    systemctl enable zabbix-server
    systemctl start zabbix-server
  EOF
  
  tags = {
    Name = "Zabbix Server"
    Application = "Zabbix"
  }
}

resource "aws_security_group" "zabbix" {
  name        = "zabbix-sg"
  description = "Security group for Zabbix"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "Zabbix Security Group"
  }
}
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update zabbix
sudo dnf update zabbix

# Debian/Ubuntu
sudo apt update
sudo apt upgrade zabbix

# Arch Linux
sudo pacman -Syu zabbix

# Alpine Linux
apk update
apk upgrade zabbix

# openSUSE
sudo zypper ref
sudo zypper update zabbix

# FreeBSD
pkg update
pkg upgrade zabbix

# Always backup before updates
/usr/local/bin/zabbix-backup

# Restart after updates
sudo systemctl restart zabbix-server
```

### Regular Maintenance Tasks

```bash
# Clean old logs
find /var/log/zabbix -name "*.log" -mtime +30 -delete

# Vacuum database (if PostgreSQL)
sudo -u postgres vacuumdb --analyze zabbix_db

# Check disk usage
df -h | grep -E "(/$|zabbix)"
du -sh /var/lib/zabbix

# Update security patches
sudo unattended-upgrade -d

# Review security logs
sudo aureport --summary
sudo journalctl -u zabbix-server | grep -i "error\|fail\|deny"
```

### Health Monitoring Checklist

- [ ] Service is running and enabled
- [ ] Web interface is accessible
- [ ] Database connections are healthy
- [ ] Disk usage is below 80%
- [ ] No critical errors in logs
- [ ] Backups are running successfully
- [ ] SSL certificates are valid
- [ ] Security updates are applied

## Additional Resources

- Official Documentation: https://docs.zabbix.org/
- GitHub Repository: https://github.com/zabbix/zabbix
- Community Forum: https://forum.zabbix.org/
- Wiki: https://wiki.zabbix.org/
- Docker Hub: https://hub.docker.com/r/zabbix/zabbix
- Security Advisories: https://security.zabbix.org/
- Best Practices: https://docs.zabbix.org/best-practices
- API Documentation: https://api.zabbix.org/
- Comparison with Nagios, Prometheus, PRTG, Datadog: https://docs.zabbix.org/comparison

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.
