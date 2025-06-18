# AWS ACM Certificate Sync Tool

A robust tool to sync AWS ACM certificates to local files for web servers (nginx, apache, haproxy, etc.). Designed for containerized environments and automation workflows.

> **⚡ Now Possible with ACM Export Feature**  
> As of [June 2025](https://aws.amazon.com/about-aws/whats-new/2025/06/aws-certificate-manager-public-certificates-use-anywhere/), AWS Certificate Manager allows exporting public certificates for use anywhere, making it possible to sync ACM-managed certificates to your own infrastructure while maintaining centralized certificate management and automatic renewals.

## Why This Tool?

While AWS ACM provides excellent certificate management within AWS services (ALB, CloudFront, etc.), many scenarios require certificates on your own servers:

- **Hybrid deployments**: On-premises servers that need AWS-managed certificates
- **Custom applications**: Services running on EC2 that don't integrate directly with ACM
- **Multi-cloud setups**: Consistent certificate management across cloud providers
- **Legacy systems**: Existing infrastructure that needs modern certificate automation
- **Development environments**: Local testing with production-like certificates

This tool bridges that gap by automatically exporting ACM certificates and deploying them to your servers with proper formatting for different web servers.

## Features

- **🔍 Multiple certificate sources**: Find certificates by ARN or AWS tags
- **🎯 Smart certificate selection**: When multiple certificates match tags, automatically selects:
  - Valid certificates over expired ones
  - Among valid certificates, the one with longest remaining validity
- **📦 Multiple output formats**: Support for nginx, apache, haproxy certificate formats
- **🎯 Multiple targets**: Deploy the same certificate to different servers/locations
- **⚡ Smart updates**: Only downloads certificates when needed (expiry check, content changes)
- **🔐 Secure handling**: Uses temporary passphrase for ACM export then stores unencrypted/encrypted as needed
- **⏰ Flexible scheduling**: Run once or as daemon with configurable schedule
- **🐳 Container-ready**: Designed for sidecar deployment patterns

## Installation

### From PyPI

```bash
pip install aws_cert_syncer
```

### From Source

```bash
git clone https://github.com/koenvo/aws_cert_syncer.git
cd aws_cert_syncer
uv sync
```

## Quick Start

1. **Create configuration file** (`config.yaml`):

```yaml
aws:
  region: us-east-1

certificates:
  - name: my-web-cert
    arn: "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012"
    targets:
      - base_dir: "/etc/ssl"
        server_type: "nginx"
        reload_command: "systemctl reload nginx"
```

2. **Run the tool**:

```bash
# Install from PyPI
aws_cert_syncer --config config.yaml

# Or run from source
python cert_sync.py --config config.yaml
```

## Configuration

### Complete Example

```yaml
aws:
  region: us-east-1

certificates:
  # Method 1: Certificate by ARN
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

  # Method 2: Certificate by tags (with smart selection)
  - name: api-cert
    tags:
      Domain: "api.example.com"
      Environment: "production"
    
    targets:
      - base_dir: "/etc/ssl"
        server_type: "apache"
        passphrase: "my-secure-password"
        reload_command: "systemctl reload apache2"

  # Method 3: Custom file paths
  - name: legacy-app
    tags:
      Name: "legacy.company.com"
    
    targets:
      - base_dir: "/opt/app/ssl"
        server_type: "nginx"
        cert_path: "/opt/app/ssl/custom-cert.pem"
        key_path: "/opt/app/ssl/custom-key.pem"
        reload_command: "docker restart legacy-app"
```

### Certificate Selection Logic

When using `tags` and multiple certificates match:

1. **Valid certificates** (ISSUED status + not expired) are preferred over invalid/expired ones
2. **Among valid certificates**, the one with the longest remaining validity is selected
3. **Detailed logging** shows all matches and selection reasoning

Example scenario:
- Certificate A: Expires in 30 days ✅ Valid
- Certificate B: Expires in 90 days ✅ Valid  
- Certificate C: Expired ❌ Invalid

**Result**: Certificate B is selected (longest validity)

## Usage

### Command Line Options

```bash
aws_cert_syncer [options]

Options:
  --config, -c    Path to configuration file (default: /config.yaml)
  --daemon, -d    Run as daemon with scheduling
  --dry-run       Show what would be done without making changes
  --help          Show help message
```

### Standalone Usage

```bash
# Run once
aws_cert_syncer --config config.yaml

# Run as daemon (uses SCHEDULE environment variable)
aws_cert_syncer --config config.yaml --daemon

# Dry run (see what would happen)
aws_cert_syncer --config config.yaml --dry-run
```

### Docker Usage

```bash
# Pull from registry (when published)
docker pull your-registry/aws_cert_syncer

# Build locally
docker build -t aws_cert_syncer .

# Run once
docker run --rm \
  -v $(pwd)/config.yaml:/config/config.yaml \
  -v ~/.aws:/home/certsync/.aws \
  -v /etc/ssl:/etc/ssl \
  aws_cert_syncer

# Run as daemon
docker run -d \
  -v $(pwd)/config.yaml:/config/config.yaml \
  -v ~/.aws:/home/certsync/.aws \
  -v /etc/ssl:/etc/ssl \
  -e SCHEDULE=02:00 \
  -e DAYS_BEFORE_EXPIRY=30 \
  aws_cert_syncer --daemon
```

### Docker Compose (Sidecar Pattern)

See [examples/docker-compose.yml.example](examples/docker-compose.yml.example) for a complete setup with nginx and haproxy.

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs cert-sync

# Force certificate sync
docker-compose exec cert-sync aws_cert_syncer --config /config/config.yaml
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | `INFO` |
| `DAYS_BEFORE_EXPIRY` | Days before expiry to trigger renewal | `30` |
| `SCHEDULE` | Daemon schedule (see formats below) | `02:00` |

### Schedule Formats

- **Time format**: `02:00` (daily at 2 AM), `14:30` (daily at 2:30 PM)
- **Interval format**: `6h` (every 6 hours), `30m` (every 30 minutes), `1h` (hourly)

## Server Types & File Formats

### Nginx
- **Files**: Separate `{name}.crt`, `{name}.key`, `{name}-chain.crt`
- **Location**: `/etc/ssl/certs/` and `/etc/ssl/private/`
- **Key format**: Unencrypted (ignores passphrase for automatic startup)
- **Permissions**: 644 (cert), 600 (key)

### Apache  
- **Files**: Separate `{name}.crt`, `{name}.key`, `{name}-chain.crt`
- **Location**: `/etc/ssl/certs/` and `/etc/ssl/private/`
- **Key format**: Supports encrypted keys with passphrase
- **Permissions**: 644 (cert), 600 (key)

### HAProxy
- **Files**: Single combined `{name}.pem` (cert + key + chain)
- **Location**: `/etc/ssl/haproxy/`
- **Key format**: Unencrypted (ignores passphrase)
- **Permissions**: 600 (combined file)

## AWS Setup

### IAM Permissions

Create an IAM policy with these permissions:

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

### AWS Credentials

The tool uses standard AWS credential chain:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
2. **AWS credentials file**: `~/.aws/credentials`
3. **IAM instance profile** (recommended for EC2/ECS)
4. **IAM roles for service accounts** (recommended for Kubernetes)

## Development

### Setup

```bash
git clone https://github.com/koenvo/aws_cert_syncer.git
cd aws_cert_syncer
uv sync
```

### Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=cert_sync

# Run specific test
uv run pytest tests/test_cert_sync.py::TestCertificateRetriever::test_find_certificate_by_tags_multiple_matches_prefers_valid
```

### Code Quality

```bash
# Format code
uv run ruff format .

# Lint code  
uv run ruff check .

# Fix auto-fixable issues
uv run ruff check . --fix
```

## Examples

Complete configuration examples are available in the [examples/](examples/) directory:

- [config.yaml.example](examples/config.yaml.example) - Complete configuration
- [docker-compose.yml.example](examples/docker-compose.yml.example) - Multi-service setup
- [Dockerfile.example](examples/Dockerfile.example) - Container build

## Troubleshooting

### Common Issues

**Certificate not found**:
- Verify ARN is correct and certificate exists in the specified region
- Check that tags match exactly (case-sensitive)
- Ensure AWS credentials have `acm:ListCertificates` permission

**Permission denied writing files**:
- Check that target directories are writable by the user running the tool
- Verify parent directories exist
- In containers, ensure proper volume mounts

**Reload command fails**:
- Test reload commands manually first
- Check that the service is installed and running
- Verify the user has permission to run the reload command
- Consider using `sudo` in reload commands if needed

**Multiple certificates found**:
- This is normal - the tool automatically selects the best one
- Check logs to see which certificate was selected and why
- Use more specific tags if you want to target a specific certificate

### Debug Mode

```bash
# Enable debug logging
LOG_LEVEL=DEBUG aws_cert_syncer --config config.yaml

# Dry run to see what would happen
aws_cert_syncer --config config.yaml --dry-run
```

### Monitoring

The tool logs all operations with structured messages:

- Certificate selection decisions
- File operations and permissions
- Reload command execution
- Error details with context

Integrate with your logging infrastructure to monitor certificate sync operations.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Security

- Report security vulnerabilities via GitHub security advisories
- Private keys are handled securely and never logged
- Temporary files are cleaned up automatically
- File permissions are set restrictively by default