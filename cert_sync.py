#!/usr/bin/env python3
"""
AWS ACM Certificate Sync Tool
Syncs ACM certificates to local files for web servers (nginx, apache, etc.)
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class Certificate:
    """Holds unencrypted certificate data"""

    def __init__(self, certificate_pem: str, private_key_pem: str, chain_pem: str):
        self.certificate_pem = certificate_pem
        self.private_key_pem = private_key_pem
        self.chain_pem = chain_pem
        self._validate()

    def _validate(self):
        """Validate certificate data"""
        if not all([self.certificate_pem, self.private_key_pem, self.chain_pem]):
            raise ValueError("Certificate, private key, and chain are all required")

    def get_certificate_hash(self) -> str:
        """Get hash of certificate for change detection"""
        return hashlib.sha256(self.certificate_pem.encode()).hexdigest()

    def get_expiry_date(self) -> datetime:
        """Get certificate expiry date"""
        cert = x509.load_pem_x509_certificate(self.certificate_pem.encode())
        return cert.not_valid_after

    def get_encrypted_private_key(self, passphrase: str) -> str:
        """Get private key encrypted with passphrase"""
        try:
            private_key = serialization.load_pem_private_key(
                self.private_key_pem.encode(), password=None
            )

            encrypted_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    passphrase.encode()
                ),
            )

            return encrypted_key.decode()

        except Exception as e:
            logging.error(f"Error encrypting private key: {e}")
            raise


class CertWriter(ABC):
    """Abstract base class for certificate writers"""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir

    @abstractmethod
    def get_file_paths(self, name: str) -> dict[str, str]:
        """Get file paths for certificate files"""
        pass

    @abstractmethod
    def write_certificate(
        self, certificate: Certificate, name: str, passphrase: str | None = None
    ) -> bool:
        """Write certificate to files"""
        pass

    def _ensure_directory(self, file_path: str):
        """Ensure parent directory exists with proper permissions"""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Set proper permissions for SSL directories
        if "private" in str(path.parent):
            path.parent.chmod(0o700)
        else:
            path.parent.chmod(0o755)

    def needs_update(
        self, certificate: Certificate, name: str, days_before_expiry: int = 30
    ) -> bool:
        """Check if certificate needs updating"""
        try:
            paths = self.get_file_paths(name)
            cert_path = paths.get("cert_path")

            # If cert file doesn't exist, we need to update
            if not cert_path or not os.path.exists(cert_path):
                logging.info(f"Certificate file missing for {name}, needs update")
                return True

            # Check if existing certificate is different (hash comparison)
            with open(cert_path) as f:
                existing_cert_pem = f.read()

            existing_hash = hashlib.sha256(existing_cert_pem.encode()).hexdigest()
            new_hash = certificate.get_certificate_hash()

            if existing_hash != new_hash:
                logging.info(f"Certificate content changed for {name}, needs update")
                return True

            # Check expiry date of existing certificate
            try:
                existing_cert = x509.load_pem_x509_certificate(
                    existing_cert_pem.encode()
                )
                expiry_date = existing_cert.not_valid_after
                days_until_expiry = (expiry_date - datetime.utcnow()).days

                if days_until_expiry <= days_before_expiry:
                    logging.info(
                        f"Certificate for {name} expires in {days_until_expiry} days, needs update"
                    )
                    return True

                logging.info(
                    f"Certificate for {name} is valid for {days_until_expiry} more days, no update needed"
                )
                return False

            except Exception as e:
                logging.error(
                    f"Error checking expiry for existing certificate {name}: {e}"
                )
                return True  # If we can't check expiry, assume we need to update

        except Exception as e:
            logging.error(f"Error checking if certificate {name} needs update: {e}")
            return True  # If we can't check, assume we need to update

    def certificate_exists_and_valid(
        self, name: str, days_before_expiry: int = 30
    ) -> bool:
        """Check if certificate exists on disk and is still valid"""
        try:
            paths = self.get_file_paths(name)
            cert_path = paths.get("cert_path")

            if not cert_path or not os.path.exists(cert_path):
                return False

            with open(cert_path) as f:
                cert_pem = f.read()

            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            expiry_date = cert.not_valid_after
            days_until_expiry = (expiry_date - datetime.utcnow()).days

            return days_until_expiry > days_before_expiry

        except Exception as e:
            logging.error(f"Error checking certificate validity for {name}: {e}")
            return False


class NginxWriter(CertWriter):
    """Certificate writer for Nginx"""

    def get_file_paths(self, name: str) -> dict[str, str]:
        return {
            "cert_path": f"{self.base_dir}/certs/{name}.crt",
            "key_path": f"{self.base_dir}/private/{name}.key",
            "chain_path": f"{self.base_dir}/certs/{name}-chain.crt",
        }

    def write_certificate(
        self, certificate: Certificate, name: str, passphrase: str | None = None
    ) -> bool:
        """Write certificate for Nginx (separate files, unencrypted key)"""
        try:
            paths = self.get_file_paths(name)

            # Ensure directories exist
            for path in paths.values():
                self._ensure_directory(path)

            # Nginx prefers unencrypted keys for automatic startup
            private_key = certificate.private_key_pem
            if passphrase:
                logging.warning(
                    f"Nginx exporter ignoring passphrase for {name} - using unencrypted key"
                )

            # Write certificate
            with open(paths["cert_path"], "w") as f:
                f.write(certificate.certificate_pem)
            os.chmod(paths["cert_path"], 0o644)

            # Write private key (unencrypted)
            with open(paths["key_path"], "w") as f:
                f.write(private_key)
            os.chmod(paths["key_path"], 0o600)

            # Write chain
            with open(paths["chain_path"], "w") as f:
                f.write(certificate.chain_pem)
            os.chmod(paths["chain_path"], 0o644)

            logging.info(f"Certificate written for Nginx: {name}")
            return True

        except Exception as e:
            logging.error(f"Error writing certificate for Nginx {name}: {e}")
            return False


class ApacheWriter(CertWriter):
    """Certificate writer for Apache"""

    def get_file_paths(self, name: str) -> dict[str, str]:
        return {
            "cert_path": f"{self.base_dir}/certs/{name}.crt",
            "key_path": f"{self.base_dir}/private/{name}.key",
            "chain_path": f"{self.base_dir}/certs/{name}-chain.crt",
        }

    def write_certificate(
        self, certificate: Certificate, name: str, passphrase: str | None = None
    ) -> bool:
        """Write certificate for Apache (separate files, supports encrypted keys)"""
        try:
            paths = self.get_file_paths(name)

            # Ensure directories exist
            for path in paths.values():
                self._ensure_directory(path)

            # Apache supports encrypted keys
            private_key = certificate.private_key_pem
            if passphrase:
                private_key = certificate.get_encrypted_private_key(passphrase)

            # Write certificate
            with open(paths["cert_path"], "w") as f:
                f.write(certificate.certificate_pem)
            os.chmod(paths["cert_path"], 0o644)

            # Write private key
            with open(paths["key_path"], "w") as f:
                f.write(private_key)
            os.chmod(paths["key_path"], 0o600)

            # Write chain
            with open(paths["chain_path"], "w") as f:
                f.write(certificate.chain_pem)
            os.chmod(paths["chain_path"], 0o644)

            logging.info(f"Certificate written for Apache: {name}")
            return True

        except Exception as e:
            logging.error(f"Error writing certificate for Apache {name}: {e}")
            return False


class HAProxyWriter(CertWriter):
    """Certificate writer for HAProxy"""

    def get_file_paths(self, name: str) -> dict[str, str]:
        return {
            "cert_path": f"{self.base_dir}/haproxy/{name}.pem"  # Combined file acts as cert_path
        }

    def write_certificate(
        self, certificate: Certificate, name: str, passphrase: str | None = None
    ) -> bool:
        """Write certificate for HAProxy (combined file, unencrypted key)"""
        try:
            paths = self.get_file_paths(name)

            # Ensure directory exists
            self._ensure_directory(paths["cert_path"])

            # HAProxy needs unencrypted key
            if passphrase:
                logging.warning(
                    f"HAProxy exporter ignoring passphrase for {name} - using unencrypted key"
                )

            # Combine cert + key + chain in single file
            combined_content = (
                certificate.certificate_pem
                + certificate.private_key_pem
                + certificate.chain_pem
            )

            with open(paths["cert_path"], "w") as f:
                f.write(combined_content)
            os.chmod(paths["cert_path"], 0o600)

            logging.info(f"Certificate written for HAProxy: {name}")
            return True

        except Exception as e:
            logging.error(f"Error writing certificate for HAProxy {name}: {e}")
            return False


class CertificateRetriever:
    """Retrieves certificates from AWS ACM"""

    def __init__(self, region: str):
        self.acm_client = boto3.client("acm", region_name=region)
        # Generate a random temporary passphrase for ACM export
        import secrets
        import string

        alphabet = string.ascii_letters + string.digits
        self.temp_passphrase = "".join(secrets.choice(alphabet) for _ in range(16))

    def find_certificate_by_arn(self, arn: str) -> str | None:
        """Find certificate by ARN"""
        try:
            self.acm_client.describe_certificate(CertificateArn=arn)
            return arn
        except Exception as e:
            logging.error(f"Certificate not found for ARN {arn}: {e}")
            return None

    def find_certificate_by_tags(self, tags: dict[str, str]) -> str | None:
        """Find certificate by matching tags, preferring valid ones with longest expiry"""
        try:
            response = self.acm_client.list_certificates()
            matching_certs = []

            for cert in response["CertificateSummary"]:
                cert_arn = cert["CertificateArn"]

                tags_response = self.acm_client.list_tags_for_certificate(
                    CertificateArn=cert_arn
                )

                cert_tags = {tag["Key"]: tag["Value"] for tag in tags_response["Tags"]}

                if all(cert_tags.get(key) == value for key, value in tags.items()):
                    # Get certificate details to check validity
                    try:
                        cert_details = self.acm_client.describe_certificate(
                            CertificateArn=cert_arn
                        )
                        not_after = cert_details["Certificate"]["NotAfter"]
                        status = cert_details["Certificate"]["Status"]

                        matching_certs.append(
                            {
                                "arn": cert_arn,
                                "not_after": not_after,
                                "status": status,
                                "is_valid": status == "ISSUED"
                                and not_after > datetime.utcnow(),
                            }
                        )
                        logging.info(
                            f"Found certificate {cert_arn} matching tags {tags}, status: {status}, expires: {not_after}"
                        )

                    except Exception as e:
                        logging.warning(
                            f"Could not get details for certificate {cert_arn}: {e}"
                        )
                        # Still include it but mark as unknown validity
                        matching_certs.append(
                            {
                                "arn": cert_arn,
                                "not_after": datetime.min,
                                "status": "UNKNOWN",
                                "is_valid": False,
                            }
                        )

            if not matching_certs:
                logging.error(f"No certificate found matching tags: {tags}")
                return None

            if len(matching_certs) == 1:
                selected = matching_certs[0]
                logging.info(f"Selected certificate {selected['arn']} (only match)")
                return selected["arn"]

            # Multiple matches - prioritize selection
            logging.info(
                f"Found {len(matching_certs)} certificates matching tags {tags}, selecting best one"
            )

            # Sort by: 1) valid certificates first, 2) longest expiry time
            matching_certs.sort(
                key=lambda x: (x["is_valid"], x["not_after"]), reverse=True
            )

            selected = matching_certs[0]
            logging.info(
                f"Selected certificate {selected['arn']} (status: {selected['status']}, expires: {selected['not_after']})"
            )

            # Log other candidates for transparency
            for i, cert in enumerate(matching_certs[1:], 1):
                logging.info(
                    f"Alternative {i}: {cert['arn']} (status: {cert['status']}, expires: {cert['not_after']})"
                )

            return selected["arn"]

        except Exception as e:
            logging.error(f"Error finding certificate by tags {tags}: {e}")
            return None

    def retrieve_certificate(self, arn: str) -> Certificate | None:
        """Retrieve certificate from ACM and return as unencrypted Certificate object"""
        try:
            # Export with temporary passphrase (required by ACM)
            response = self.acm_client.export_certificate(
                CertificateArn=arn, Passphrase=self.temp_passphrase.encode()
            )

            # Decrypt the private key immediately
            encrypted_key = response["PrivateKey"]
            private_key = serialization.load_pem_private_key(
                encrypted_key.encode(), password=self.temp_passphrase.encode()
            )

            # Get unencrypted private key
            unencrypted_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            return Certificate(
                certificate_pem=response["Certificate"],
                private_key_pem=unencrypted_key.decode(),
                chain_pem=response["CertificateChain"],
            )

        except Exception as e:
            logging.error(f"Error retrieving certificate {arn}: {e}")
            return None


def create_writer(writer_type: str, base_dir: str) -> CertWriter:
    """Factory function to create appropriate writer"""
    writers = {"nginx": NginxWriter, "apache": ApacheWriter, "haproxy": HAProxyWriter}

    if writer_type not in writers:
        raise ValueError(
            f"Unknown writer type: {writer_type}. Available: {list(writers.keys())}"
        )

    return writers[writer_type](base_dir)


class CertSyncManager:
    """Main certificate sync manager"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self.retriever = CertificateRetriever(self.config["aws"]["region"])
        self.setup_logging()

    def _load_config(self) -> dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            logging.error(f"Error loading config from {self.config_path}: {e}")
            raise

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        logging.basicConfig(
            level=getattr(logging, log_level),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)],
        )

    def _execute_command(self, command: str, cert_name: str) -> bool:
        """Execute reload command after certificate update"""
        try:
            import shlex
            import subprocess  # nosec B404 - subprocess needed for reload commands

            logging.info(f"Executing reload command for {cert_name}: {command}")

            # Parse command safely to avoid shell injection
            result = subprocess.run(  # nosec B603 - command is user-configured and parsed with shlex for safety
                shlex.split(command), capture_output=True, text=True, timeout=30
            )

            if result.returncode == 0:
                logging.info(f"Reload command successful for {cert_name}")
                return True
            else:
                logging.error(f"Reload command failed for {cert_name}: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            logging.error(f"Reload command timed out for {cert_name}")
            return False
        except Exception as e:
            logging.error(f"Error executing reload command for {cert_name}: {e}")
            return False

    def sync_certificate(self, cert_config: dict[str, Any]) -> bool:
        """Sync a single certificate to all its targets"""
        cert_name = cert_config["name"]
        logging.info(f"Starting sync for certificate: {cert_name}")

        try:
            # Find certificate ARN
            cert_arn = None
            if "arn" in cert_config:
                cert_arn = self.retriever.find_certificate_by_arn(cert_config["arn"])
            elif "tags" in cert_config:
                cert_arn = self.retriever.find_certificate_by_tags(cert_config["tags"])
            else:
                logging.error(
                    f"Certificate {cert_name} must have either 'arn' or 'tags' specified"
                )
                return False

            if not cert_arn:
                logging.error(f"Could not find certificate for {cert_name}")
                return False

            # Get targets (fallback to single storage for backwards compatibility)
            targets = cert_config.get("targets", [])
            if not targets and "storage" in cert_config:
                # Backwards compatibility: convert old storage format to targets
                storage = cert_config["storage"]
                storage["reload_command"] = cert_config.get("reload_command", "")
                targets = [storage]

            if not targets:
                logging.error(f"Certificate {cert_name} has no targets specified")
                return False

            # Check if any target needs update
            days_before_expiry = int(os.getenv("DAYS_BEFORE_EXPIRY", "30"))
            needs_retrieval = False

            for target in targets:
                server_type = target.get("server_type", "nginx")
                base_dir = target["base_dir"]
                writer = create_writer(server_type, base_dir)

                if not writer.certificate_exists_and_valid(
                    cert_name, days_before_expiry
                ):
                    needs_retrieval = True
                    break

            if not needs_retrieval:
                logging.info(
                    f"Certificate {cert_name} is valid on all targets, skipping sync"
                )
                return True

            # Retrieve certificate from ACM (only if needed)
            certificate = self.retriever.retrieve_certificate(cert_arn)
            if not certificate:
                logging.error(f"Failed to retrieve certificate for {cert_name}")
                return False

            # Sync to all targets
            success_count = 0
            for i, target in enumerate(targets):
                target_name = f"{cert_name}-target-{i}"
                logging.info(f"Syncing to target {i+1}/{len(targets)} for {cert_name}")

                try:
                    server_type = target.get("server_type", "nginx")
                    base_dir = target["base_dir"]
                    writer = create_writer(server_type, base_dir)

                    # Check if this specific target needs update
                    if not writer.needs_update(
                        certificate, cert_name, days_before_expiry
                    ):
                        logging.info(
                            f"Target {i+1} for {cert_name} does not need update"
                        )
                        success_count += 1
                        continue

                    # Write certificate to this target
                    passphrase = target.get("passphrase", "")
                    success = writer.write_certificate(
                        certificate, cert_name, passphrase if passphrase else None
                    )

                    if success:
                        # Execute reload command for this target
                        if "reload_command" in target and target["reload_command"]:
                            self._execute_command(target["reload_command"], target_name)
                        success_count += 1
                    else:
                        logging.error(
                            f"Failed to write certificate to target {i+1} for {cert_name}"
                        )

                except Exception as e:
                    logging.error(f"Error syncing target {i+1} for {cert_name}: {e}")

            if success_count == len(targets):
                logging.info(
                    f"Successfully synced certificate {cert_name} to all {len(targets)} targets"
                )
                return True
            else:
                logging.error(
                    f"Synced certificate {cert_name} to {success_count}/{len(targets)} targets"
                )
                return False

        except Exception as e:
            logging.error(f"Error syncing certificate {cert_name}: {e}")
            return False

    def sync_all_certificates(self) -> bool:
        """Sync all certificates from config"""
        certificates = self.config.get("certificates", [])

        if not certificates:
            logging.warning("No certificates configured")
            return True

        success_count = 0
        total_count = len(certificates)

        for cert_config in certificates:
            if self.sync_certificate(cert_config):
                success_count += 1

        logging.info(f"Synced {success_count}/{total_count} certificates successfully")
        return success_count == total_count

    def run_once(self) -> bool:
        """Run certificate sync once"""
        logging.info("Starting certificate sync run")
        try:
            return self.sync_all_certificates()
        except Exception as e:
            logging.error(f"Error during certificate sync: {e}")
            return False

    def run_daemon(self):
        """Run as daemon with scheduling"""
        import time

        import schedule

        # Parse schedule from environment variable (default: daily at 2 AM)
        schedule_spec = os.getenv("SCHEDULE", "02:00")

        try:
            if ":" in schedule_spec:
                # Time format like "02:00"
                schedule.every().day.at(schedule_spec).do(self.sync_all_certificates)
                logging.info(f"Scheduled daily sync at {schedule_spec}")
            else:
                # Interval format like "1h", "30m"
                if schedule_spec.endswith("h"):
                    hours = int(schedule_spec[:-1])
                    schedule.every(hours).hours.do(self.sync_all_certificates)
                    logging.info(f"Scheduled sync every {hours} hours")
                elif schedule_spec.endswith("m"):
                    minutes = int(schedule_spec[:-1])
                    schedule.every(minutes).minutes.do(self.sync_all_certificates)
                    logging.info(f"Scheduled sync every {minutes} minutes")
                else:
                    raise ValueError(f"Invalid schedule format: {schedule_spec}")

            # Run initial sync
            self.sync_all_certificates()

            # Keep running scheduled tasks
            logging.info("Certificate sync daemon started")
            while True:
                schedule.run_pending()
                time.sleep(60)  # Check every minute

        except KeyboardInterrupt:
            logging.info("Certificate sync daemon stopped")
        except Exception as e:
            logging.error(f"Error in daemon mode: {e}")
            raise


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AWS ACM Certificate Sync Tool")
    parser.add_argument(
        "--config",
        "-c",
        default="/config.yaml",
        help="Path to configuration file (default: /config.yaml)",
    )
    parser.add_argument(
        "--daemon", "-d", action="store_true", help="Run as daemon with scheduling"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )

    args = parser.parse_args()

    if args.dry_run:
        logging.info("DRY RUN MODE - No changes will be made")
        # TODO: Implement dry run mode
        return

    try:
        manager = CertSyncManager(args.config)

        if args.daemon:
            manager.run_daemon()
        else:
            success = manager.run_once()
            sys.exit(0 if success else 1)

    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
