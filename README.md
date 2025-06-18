# AWS ACM Certificate Sync Tool

A tool to sync AWS ACM certificates to local files for web servers (nginx, apache, haproxy, etc.). Designed to run as a sidecar container in Docker environments.

## Features

- **Multiple certificate sources**: Find certificates by ARN or AWS tags
- **Multiple output formats**: Support for nginx, apache, haproxy certificate formats
- **Multiple targets**: Deploy the same certificate to different servers/locations
- **Smart updates**: Only downloads certificates when needed (expiry check, content changes)
- **Secure handling**: Uses temporary passphrase for ACM export then stores unencrypted/encrypted as needed
- **Flexible scheduling**: Run once or as daemon with configurable schedule
- **Container-ready**: Designed for sidecar deployment patterns

## Configuration

Create a `config.yaml` file:

```yaml
aws:
  region: us-east-1

certificates:
  # Certificate with multiple targets
  - name: my-domain-cert
    arn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
    
    targets:
      # Deploy to nginx
      - base_dir: "/etc/ssl"
        server_type: "nginx"
        passphrase: ""
        reload_command: "systemctl reload nginx"
      
      # Deploy to haproxy (same cert, different format)
      - base_dir: "/opt/haproxy/ssl"
        server_type: "haproxy"
        reload_command: "systemctl reload haproxy"

  # Certificate found by tags
  - name: api-cert
    tags:
      Domain: "api.example.com"
      Environment: "production"
    
    targets:
      - base_dir: "/etc/ssl"
        server_type: "apache"
        passphrase: "my-secure-password"
        reload_command: "systemctl reload apache2"
```

## Usage

### Standalone

```bash
# Install dependencies
poetry install

# Run once
python cert_sync.py --config config.yaml

# Run as daemon
python cert_sync.py --config config.yaml --daemon
```

### Docker

```bash
# Build image
docker build -t cert-sync .

# Run once
docker run --rm \
  -v $(pwd)/config.yaml:/config/config.yaml \
  -v ~/.aws:/home/certsync/.aws \
  -v /etc/ssl:/etc/ssl \
  cert-sync

# Run as daemon
docker run -d \
  -v $(pwd)/config.yaml:/config/config.yaml \
  -v ~/.aws:/home/certsync/.aws \
  -v /etc/ssl:/etc/ssl \
  -e SCHEDULE=02:00 \
  cert-sync python cert_sync.py --config /config/config.yaml --daemon
```

### Docker Compose (Sidecar Pattern)

```bash
# Start all services (nginx + cert-sync sidecar)
docker-compose up -d

# View logs
docker-compose logs cert-sync

# Force certificate sync
docker-compose exec cert-sync python cert_sync.py --config /config/config.yaml
```

## Environment Variables

- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR) - default: INFO
- `DAYS_BEFORE_EXPIRY`: Days before expiry to trigger renewal - default: 30
- `SCHEDULE`: Daemon schedule format:
  - Time format: `02:00` (daily at 2 AM)
  - Interval format: `6h` (every 6 hours), `30m` (every 30 minutes)

## Server Types

### Nginx
- Creates separate files: `cert.crt`, `key.key`, `chain-cert.crt`
- Uses unencrypted private keys (ignores passphrase)
- Files stored in `/etc/ssl/certs/` and `/etc/ssl/private/`

### Apache
- Creates separate files: `cert.crt`, `key.key`, `chain-cert.crt`
- Supports encrypted private keys with passphrase
- Files stored in `/etc/ssl/certs/` and `/etc/ssl/private/`

### HAProxy
- Creates single combined file: `cert.pem` (cert + key + chain)
- Uses unencrypted private keys (ignores passphrase)
- File stored in `/etc/ssl/haproxy/`

## Security

- The tool exports certificates from ACM using a temporary passphrase
- Private keys are immediately decrypted and stored according to target requirements
- Private key files are created with 600 permissions (owner read/write only)
- Certificate files are created with 644 permissions (world readable)
- Private key directories are created with 700 permissions

## AWS Permissions

The tool needs these IAM permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "acm:ListCertificates",
                "acm:DescribeCertificate",
                "acm:ExportCertificate",
                "acm:ListTagsForCertificate"
            ],
            "Resource": "*"
        }
    ]
}
```

## Troubleshooting

- Check logs with `docker-compose logs cert-sync`
- Verify AWS credentials and permissions
- Ensure certificate ARNs or tags are correct
- Check file permissions on target directories
- Verify reload commands work manually