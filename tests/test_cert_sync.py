import os
from datetime import datetime, timedelta
from unittest.mock import MagicMock, mock_open, patch

import pytest

from cert_sync import (
    ApacheWriter,
    Certificate,
    CertificateRetriever,
    CertSyncManager,
    HAProxyWriter,
    NginxWriter,
    create_writer,
)


class TestCertificate:
    """Test Certificate class"""

    def test_certificate_creation(self):
        cert = Certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )
        assert cert.certificate_pem is not None
        assert cert.private_key_pem is not None
        assert cert.chain_pem is not None

    def test_certificate_validation_fails(self):
        with pytest.raises(ValueError):
            Certificate("", "", "")

    def test_get_certificate_hash(self):
        cert = Certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )
        hash1 = cert.get_certificate_hash()
        hash2 = cert.get_certificate_hash()
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex length


class TestNginxWriter:
    """Test NginxWriter class"""

    def test_get_file_paths(self):
        writer = NginxWriter("/etc/ssl")
        paths = writer.get_file_paths("test-cert")

        expected = {
            "cert_path": "/etc/ssl/certs/test-cert.crt",
            "key_path": "/etc/ssl/private/test-cert.key",
            "chain_path": "/etc/ssl/certs/test-cert-chain.crt",
        }
        assert paths == expected

    @patch("os.makedirs")
    @patch("os.chmod")
    @patch("builtins.open", new_callable=mock_open)
    def test_write_certificate_success(self, mock_file, mock_chmod, mock_makedirs):
        writer = NginxWriter("/etc/ssl")
        cert = Certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )

        with patch.object(writer, "_ensure_directory"):
            result = writer.write_certificate(cert, "test-cert")

        assert result is True
        assert mock_file.call_count == 3  # cert, key, chain files
        assert mock_chmod.call_count == 3

    @patch("os.makedirs")
    @patch("os.chmod")
    @patch("builtins.open", side_effect=OSError("Permission denied"))
    def test_write_certificate_failure(self, mock_file, mock_chmod, mock_makedirs):
        writer = NginxWriter("/etc/ssl")
        cert = Certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )

        with patch.object(writer, "_ensure_directory"):
            result = writer.write_certificate(cert, "test-cert")

        assert result is False

    def create_test_certificate_pem(self, days_until_expiry=30):
        """Create a test certificate PEM with specified expiry"""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.example.com"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=days_until_expiry))
            .sign(private_key, hashes.SHA256())
        )

        # Return PEM
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_needs_update_certificate_missing(self, mock_file, mock_exists):
        """Test needs_update when certificate file doesn't exist"""
        mock_exists.return_value = False

        writer = NginxWriter("/etc/ssl")
        cert = Certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )

        result = writer.needs_update(cert, "test-cert")
        assert result is True

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_needs_update_certificate_changed(self, mock_file, mock_exists):
        """Test needs_update when certificate content has changed"""
        mock_exists.return_value = True

        # Mock existing certificate with different content
        mock_file.return_value.read.return_value = (
            "-----BEGIN CERTIFICATE-----\nold-cert\n-----END CERTIFICATE-----"
        )

        writer = NginxWriter("/etc/ssl")
        cert = Certificate(
            certificate_pem="-----BEGIN CERTIFICATE-----\nnew-cert\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )

        result = writer.needs_update(cert, "test-cert")
        assert result is True

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_needs_update_certificate_expiring(self, mock_file, mock_exists):
        """Test needs_update when certificate is expiring soon"""
        mock_exists.return_value = True

        # Create certificate expiring in 10 days
        expiring_cert_pem = self.create_test_certificate_pem(days_until_expiry=10)
        mock_file.return_value.read.return_value = expiring_cert_pem

        writer = NginxWriter("/etc/ssl")
        cert = Certificate(
            certificate_pem=expiring_cert_pem,
            private_key_pem="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )

        # Check with 30 days threshold - should need update
        result = writer.needs_update(cert, "test-cert", days_before_expiry=30)
        assert result is True

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_needs_update_certificate_valid(self, mock_file, mock_exists):
        """Test needs_update when certificate is still valid"""
        mock_exists.return_value = True

        # Create certificate expiring in 60 days
        valid_cert_pem = self.create_test_certificate_pem(days_until_expiry=60)
        mock_file.return_value.read.return_value = valid_cert_pem

        writer = NginxWriter("/etc/ssl")
        cert = Certificate(
            certificate_pem=valid_cert_pem,
            private_key_pem="-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            chain_pem="-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        )

        # Check with 30 days threshold - should NOT need update
        result = writer.needs_update(cert, "test-cert", days_before_expiry=30)
        assert result is False

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_certificate_exists_and_valid_missing(self, mock_file, mock_exists):
        """Test certificate_exists_and_valid when file doesn't exist"""
        mock_exists.return_value = False

        writer = NginxWriter("/etc/ssl")
        result = writer.certificate_exists_and_valid("test-cert")
        assert result is False

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_certificate_exists_and_valid_expiring(self, mock_file, mock_exists):
        """Test certificate_exists_and_valid when certificate is expiring"""
        mock_exists.return_value = True

        # Create certificate expiring in 15 days
        expiring_cert_pem = self.create_test_certificate_pem(days_until_expiry=15)
        mock_file.return_value.read.return_value = expiring_cert_pem

        writer = NginxWriter("/etc/ssl")
        # Check with 30 days threshold - should be invalid
        result = writer.certificate_exists_and_valid("test-cert", days_before_expiry=30)
        assert result is False

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_certificate_exists_and_valid_ok(self, mock_file, mock_exists):
        """Test certificate_exists_and_valid when certificate is still valid"""
        mock_exists.return_value = True

        # Create certificate expiring in 60 days
        valid_cert_pem = self.create_test_certificate_pem(days_until_expiry=60)
        mock_file.return_value.read.return_value = valid_cert_pem

        writer = NginxWriter("/etc/ssl")
        # Check with 30 days threshold - should be valid
        result = writer.certificate_exists_and_valid("test-cert", days_before_expiry=30)
        assert result is True


class TestCertificateRetriever:
    """Test CertificateRetriever class"""

    @patch("boto3.client")
    def test_init(self, mock_boto3_client):
        retriever = CertificateRetriever("us-east-1")
        mock_boto3_client.assert_called_once_with("acm", region_name="us-east-1")
        # Passphrase should be 16 characters long and alphanumeric
        assert len(retriever.temp_passphrase) == 16
        assert retriever.temp_passphrase.isalnum()

    @patch("boto3.client")
    def test_find_certificate_by_arn_success(self, mock_boto3_client):
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm
        mock_acm.describe_certificate.return_value = {}

        retriever = CertificateRetriever("us-east-1")
        arn = "arn:aws:acm:us-east-1:123456789012:certificate/test"

        result = retriever.find_certificate_by_arn(arn)

        assert result == arn
        mock_acm.describe_certificate.assert_called_once_with(CertificateArn=arn)

    @patch("boto3.client")
    def test_find_certificate_by_arn_not_found(self, mock_boto3_client):
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm
        mock_acm.describe_certificate.side_effect = Exception("Not found")

        retriever = CertificateRetriever("us-east-1")
        arn = "arn:aws:acm:us-east-1:123456789012:certificate/test"

        result = retriever.find_certificate_by_arn(arn)

        assert result is None

    @patch("boto3.client")
    def test_find_certificate_by_tags_success(self, mock_boto3_client):
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm

        # Mock certificate list
        mock_acm.list_certificates.return_value = {
            "CertificateSummary": [
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/test1"
                },
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/test2"
                },
            ]
        }

        # Mock tags for first certificate (no match)
        mock_acm.list_tags_for_certificate.side_effect = [
            {"Tags": [{"Key": "Environment", "Value": "dev"}]},
            {
                "Tags": [
                    {"Key": "Environment", "Value": "prod"},
                    {"Key": "Domain", "Value": "example.com"},
                ]
            },
        ]

        retriever = CertificateRetriever("us-east-1")
        tags = {"Environment": "prod", "Domain": "example.com"}

        result = retriever.find_certificate_by_tags(tags)

        assert result == "arn:aws:acm:us-east-1:123456789012:certificate/test2"

    @patch("boto3.client")
    def test_find_certificate_by_tags_not_found(self, mock_boto3_client):
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm

        mock_acm.list_certificates.return_value = {
            "CertificateSummary": [
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/test1"
                }
            ]
        }

        mock_acm.list_tags_for_certificate.return_value = {
            "Tags": [{"Key": "Environment", "Value": "dev"}]
        }

        retriever = CertificateRetriever("us-east-1")
        tags = {"Environment": "prod"}

        result = retriever.find_certificate_by_tags(tags)

        assert result is None

    @patch("boto3.client")
    def test_find_certificate_by_tags_multiple_matches_prefers_valid(
        self, mock_boto3_client
    ):
        """Test that when multiple certificates match tags, it prefers valid ones"""
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm

        # Mock certificate list
        mock_acm.list_certificates.return_value = {
            "CertificateSummary": [
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/expired"
                },
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/valid"
                },
            ]
        }

        # Both certificates have matching tags
        mock_acm.list_tags_for_certificate.return_value = {
            "Tags": [
                {"Key": "Environment", "Value": "prod"},
                {"Key": "Domain", "Value": "example.com"},
            ]
        }

        # Mock certificate details - first is expired, second is valid
        future_date = datetime.utcnow() + timedelta(days=90)
        past_date = datetime.utcnow() - timedelta(days=30)

        mock_acm.describe_certificate.side_effect = [
            {
                "Certificate": {
                    "Status": "ISSUED",
                    "NotAfter": past_date,  # Expired
                }
            },
            {
                "Certificate": {
                    "Status": "ISSUED",
                    "NotAfter": future_date,  # Valid
                }
            },
        ]

        retriever = CertificateRetriever("us-east-1")
        tags = {"Environment": "prod", "Domain": "example.com"}

        result = retriever.find_certificate_by_tags(tags)

        # Should select the valid certificate
        assert result == "arn:aws:acm:us-east-1:123456789012:certificate/valid"

    @patch("boto3.client")
    def test_find_certificate_by_tags_multiple_valid_prefers_longest_expiry(
        self, mock_boto3_client
    ):
        """Test that among valid certificates, it prefers the one with longest validity"""
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm

        # Mock certificate list
        mock_acm.list_certificates.return_value = {
            "CertificateSummary": [
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/short"
                },
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/long"
                },
            ]
        }

        # Both certificates have matching tags
        mock_acm.list_tags_for_certificate.return_value = {
            "Tags": [{"Key": "Environment", "Value": "prod"}]
        }

        # Mock certificate details - both valid but different expiry times
        short_expiry = datetime.utcnow() + timedelta(days=30)
        long_expiry = datetime.utcnow() + timedelta(days=90)

        mock_acm.describe_certificate.side_effect = [
            {"Certificate": {"Status": "ISSUED", "NotAfter": short_expiry}},
            {"Certificate": {"Status": "ISSUED", "NotAfter": long_expiry}},
        ]

        retriever = CertificateRetriever("us-east-1")
        tags = {"Environment": "prod"}

        result = retriever.find_certificate_by_tags(tags)

        # Should select the certificate with longer validity
        assert result == "arn:aws:acm:us-east-1:123456789012:certificate/long"

    @patch("boto3.client")
    @patch("cert_sync.serialization")
    def test_retrieve_certificate_success(self, mock_serialization, mock_boto3_client):
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm

        # Mock ACM export response
        mock_acm.export_certificate.return_value = {
            "Certificate": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            "PrivateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nkey\n-----END ENCRYPTED PRIVATE KEY-----",
            "CertificateChain": "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
        }

        # Mock private key operations
        mock_private_key = MagicMock()
        mock_serialization.load_pem_private_key.return_value = mock_private_key
        mock_private_key.private_bytes.return_value = (
            b"-----BEGIN PRIVATE KEY-----\nunencrypted\n-----END PRIVATE KEY-----"
        )

        retriever = CertificateRetriever("us-east-1")
        arn = "arn:aws:acm:us-east-1:123456789012:certificate/test"

        result = retriever.retrieve_certificate(arn)

        assert result is not None
        assert isinstance(result, Certificate)
        # Verify export was called with the right ARN and a bytes passphrase
        call_args = mock_acm.export_certificate.call_args
        assert call_args[1]["CertificateArn"] == arn
        assert isinstance(call_args[1]["Passphrase"], bytes)
        assert len(call_args[1]["Passphrase"]) == 16


class TestCertSyncManager:
    """Test CertSyncManager class"""

    def create_test_config(self):
        return {
            "aws": {"region": "us-east-1"},
            "certificates": [
                {
                    "name": "test-cert",
                    "arn": "arn:aws:acm:us-east-1:123456789012:certificate/test",
                    "targets": [
                        {
                            "base_dir": "/etc/ssl",
                            "server_type": "nginx",
                            "passphrase": "",
                            "reload_command": "systemctl reload nginx",
                        }
                    ],
                }
            ],
        }

    @patch("builtins.open", new_callable=mock_open)
    @patch("yaml.safe_load")
    @patch("cert_sync.CertificateRetriever")
    def test_init_success(self, mock_retriever, mock_yaml_load, mock_file):
        config = self.create_test_config()
        mock_yaml_load.return_value = config

        manager = CertSyncManager("/config/test.yaml")

        assert manager.config == config
        mock_retriever.assert_called_once_with("us-east-1")

    @patch("builtins.open", side_effect=FileNotFoundError())
    def test_init_config_not_found(self, mock_file):
        with pytest.raises(FileNotFoundError):
            CertSyncManager("/config/nonexistent.yaml")

    @patch("builtins.open", new_callable=mock_open)
    @patch("yaml.safe_load")
    @patch("cert_sync.CertificateRetriever")
    def test_sync_certificate_by_arn_success(
        self, mock_retriever_class, mock_yaml_load, mock_file
    ):
        config = self.create_test_config()
        mock_yaml_load.return_value = config

        # Mock retriever
        mock_retriever = MagicMock()
        mock_retriever_class.return_value = mock_retriever
        mock_retriever.find_certificate_by_arn.return_value = config["certificates"][0][
            "arn"
        ]

        # Mock certificate
        mock_cert = MagicMock()
        mock_retriever.retrieve_certificate.return_value = mock_cert

        # Mock writer
        with patch("cert_sync.create_writer") as mock_create_writer:
            mock_writer = MagicMock()
            mock_create_writer.return_value = mock_writer
            mock_writer.certificate_exists_and_valid.return_value = False
            mock_writer.needs_update.return_value = True
            mock_writer.write_certificate.return_value = True

            with patch.object(CertSyncManager, "_execute_command", return_value=True):
                manager = CertSyncManager("/config/test.yaml")
                result = manager.sync_certificate(config["certificates"][0])

        assert result is True
        mock_writer.write_certificate.assert_called_once()

    @patch("builtins.open", new_callable=mock_open)
    @patch("yaml.safe_load")
    @patch("cert_sync.CertificateRetriever")
    def test_sync_certificate_by_tags_success(
        self, mock_retriever_class, mock_yaml_load, mock_file
    ):
        config = {
            "aws": {"region": "us-east-1"},
            "certificates": [
                {
                    "name": "test-cert",
                    "tags": {"Environment": "prod", "Domain": "example.com"},
                    "targets": [
                        {
                            "base_dir": "/etc/ssl",
                            "server_type": "nginx",
                            "passphrase": "",
                            "reload_command": "systemctl reload nginx",
                        }
                    ],
                }
            ],
        }
        mock_yaml_load.return_value = config

        # Mock retriever
        mock_retriever = MagicMock()
        mock_retriever_class.return_value = mock_retriever
        mock_retriever.find_certificate_by_tags.return_value = (
            "arn:aws:acm:us-east-1:123456789012:certificate/found"
        )

        # Mock certificate
        mock_cert = MagicMock()
        mock_retriever.retrieve_certificate.return_value = mock_cert

        # Mock writer
        with patch("cert_sync.create_writer") as mock_create_writer:
            mock_writer = MagicMock()
            mock_create_writer.return_value = mock_writer
            mock_writer.certificate_exists_and_valid.return_value = False
            mock_writer.needs_update.return_value = True
            mock_writer.write_certificate.return_value = True

            with patch.object(CertSyncManager, "_execute_command", return_value=True):
                manager = CertSyncManager("/config/test.yaml")
                result = manager.sync_certificate(config["certificates"][0])

        assert result is True
        mock_retriever.find_certificate_by_tags.assert_called_once_with(
            {"Environment": "prod", "Domain": "example.com"}
        )

    @patch("builtins.open", new_callable=mock_open)
    @patch("yaml.safe_load")
    @patch("cert_sync.CertificateRetriever")
    def test_sync_certificate_not_found(
        self, mock_retriever_class, mock_yaml_load, mock_file
    ):
        config = self.create_test_config()
        mock_yaml_load.return_value = config

        # Mock retriever
        mock_retriever = MagicMock()
        mock_retriever_class.return_value = mock_retriever
        mock_retriever.find_certificate_by_arn.return_value = None

        manager = CertSyncManager("/config/test.yaml")
        result = manager.sync_certificate(config["certificates"][0])

        assert result is False

    @patch("builtins.open", new_callable=mock_open)
    @patch("yaml.safe_load")
    @patch("cert_sync.CertificateRetriever")
    def test_sync_certificate_already_valid(
        self, mock_retriever_class, mock_yaml_load, mock_file
    ):
        config = self.create_test_config()
        mock_yaml_load.return_value = config

        # Mock retriever
        mock_retriever = MagicMock()
        mock_retriever_class.return_value = mock_retriever
        mock_retriever.find_certificate_by_arn.return_value = config["certificates"][0][
            "arn"
        ]

        # Mock writer - certificate is already valid
        with patch("cert_sync.create_writer") as mock_create_writer:
            mock_writer = MagicMock()
            mock_create_writer.return_value = mock_writer
            mock_writer.certificate_exists_and_valid.return_value = True

            manager = CertSyncManager("/config/test.yaml")
            result = manager.sync_certificate(config["certificates"][0])

        assert result is True
        # Should not call retrieve_certificate since cert is already valid
        mock_retriever.retrieve_certificate.assert_not_called()

    @patch("subprocess.run")
    def test_execute_command_success(self, mock_subprocess):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result

        with (
            patch("builtins.open", new_callable=mock_open),
            patch("yaml.safe_load", return_value=self.create_test_config()),
            patch("cert_sync.CertificateRetriever"),
        ):
            manager = CertSyncManager("/config/test.yaml")
            result = manager._execute_command("systemctl reload nginx", "test-cert")

        assert result is True
        mock_subprocess.assert_called_once()

    @patch("subprocess.run")
    def test_execute_command_failure(self, mock_subprocess):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Service not found"
        mock_subprocess.return_value = mock_result

        with (
            patch("builtins.open", new_callable=mock_open),
            patch("yaml.safe_load", return_value=self.create_test_config()),
            patch("cert_sync.CertificateRetriever"),
        ):
            manager = CertSyncManager("/config/test.yaml")
            result = manager._execute_command("systemctl reload nginx", "test-cert")

        assert result is False


class TestCreateWriter:
    """Test create_writer factory function"""

    def test_create_nginx_writer(self):
        writer = create_writer("nginx", "/etc/ssl")
        assert isinstance(writer, NginxWriter)
        assert writer.base_dir == "/etc/ssl"

    def test_create_apache_writer(self):
        writer = create_writer("apache", "/etc/ssl")
        assert isinstance(writer, ApacheWriter)
        assert writer.base_dir == "/etc/ssl"

    def test_create_haproxy_writer(self):
        writer = create_writer("haproxy", "/etc/ssl")
        assert isinstance(writer, HAProxyWriter)
        assert writer.base_dir == "/etc/ssl"

    def test_create_unknown_writer(self):
        with pytest.raises(ValueError, match="Unknown writer type: unknown"):
            create_writer("unknown", "/etc/ssl")


# Integration test
class TestIntegration:
    """Integration tests that test the full flow"""

    def create_test_certificate_pem(self, days_until_expiry=30):
        """Create a test certificate PEM with specified expiry"""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.example.com"),
            ]
        )

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=days_until_expiry))
            .sign(private_key, hashes.SHA256())
        )

        # Return PEM
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def test_full_sync_flow_nginx(self):
        """Test complete sync flow from config to nginx files"""

        config = {
            "aws": {"region": "us-east-1"},
            "certificates": [
                {
                    "name": "example-com",
                    "arn": "arn:aws:acm:us-east-1:123456789012:certificate/test",
                    "targets": [
                        {
                            "base_dir": "/tmp/ssl",
                            "server_type": "nginx",
                            "passphrase": "",
                            "reload_command": "echo 'nginx reloaded'",
                        }
                    ],
                }
            ],
        }

        with (
            patch("yaml.safe_load", return_value=config),
            patch("os.path.exists", return_value=False),
            patch("subprocess.run") as mock_subprocess,
            patch("builtins.open", mock_open()) as mock_file,
            patch("cert_sync.serialization") as mock_serialization,
            patch("boto3.client") as mock_boto3_client,
            patch("os.chmod") as mock_os_chmod,
            patch("pathlib.Path.chmod"),
            patch("pathlib.Path.mkdir"),
        ):
            # Mock boto3 ACM client
            mock_acm = MagicMock()
            mock_boto3_client.return_value = mock_acm
            mock_acm.describe_certificate.return_value = {}
            mock_acm.export_certificate.return_value = {
                "Certificate": "-----BEGIN CERTIFICATE-----\ntest-cert\n-----END CERTIFICATE-----",
                "PrivateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\ntest-key\n-----END ENCRYPTED PRIVATE KEY-----",
                "CertificateChain": "-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----",
            }

            # Mock private key decryption
            mock_private_key = MagicMock()
            mock_serialization.load_pem_private_key.return_value = mock_private_key
            mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nunencrypted-key\n-----END PRIVATE KEY-----"

            # Mock subprocess for reload command
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_subprocess.return_value = mock_result

            # Run the sync
            manager = CertSyncManager("/config/test.yaml")
            result = manager.sync_all_certificates()

            # Verify success
            assert result is True

            # Verify ACM calls
            mock_acm.describe_certificate.assert_called_once()
            mock_acm.export_certificate.assert_called_once()

            # Verify file writes (cert, key, chain)
            assert mock_file.call_count >= 3

            # Verify reload command
            mock_subprocess.assert_called_once()

            # Verify permissions were set
            assert mock_os_chmod.call_count >= 3

    def test_certificate_refresh_on_expiry(self):
        """Test certificate refresh when existing certificate is expiring"""

        config = {
            "aws": {"region": "us-east-1"},
            "certificates": [
                {
                    "name": "expiring-cert",
                    "arn": "arn:aws:acm:us-east-1:123456789012:certificate/test",
                    "targets": [
                        {
                            "base_dir": "/tmp/ssl",
                            "server_type": "nginx",
                            "passphrase": "",
                            "reload_command": "echo 'nginx reloaded'",
                        }
                    ],
                }
            ],
        }

        # Mock existing expiring certificate on disk (expires in 15 days)
        expiring_cert_pem = self.create_test_certificate_pem(days_until_expiry=15)

        with (
            patch("yaml.safe_load", return_value=config),
            patch("os.path.exists", return_value=True),
            patch("subprocess.run") as mock_subprocess,
            patch("builtins.open", mock_open(read_data=expiring_cert_pem)) as mock_file,
            patch("cert_sync.serialization") as mock_serialization,
            patch("boto3.client") as mock_boto3_client,
            patch("os.chmod"),
            patch("pathlib.Path.chmod"),
            patch("pathlib.Path.mkdir"),
            patch.dict(os.environ, {"DAYS_BEFORE_EXPIRY": "30"}),
        ):
            # Mock boto3 ACM client
            mock_acm = MagicMock()
            mock_boto3_client.return_value = mock_acm
            mock_acm.describe_certificate.return_value = {}

            # Mock ACM returning new certificate
            new_cert_pem = self.create_test_certificate_pem(days_until_expiry=90)
            mock_acm.export_certificate.return_value = {
                "Certificate": new_cert_pem,
                "PrivateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----\ntest-key\n-----END ENCRYPTED PRIVATE KEY-----",
                "CertificateChain": "-----BEGIN CERTIFICATE-----\ntest-chain\n-----END CERTIFICATE-----",
            }

            # Mock private key decryption
            mock_private_key = MagicMock()
            mock_serialization.load_pem_private_key.return_value = mock_private_key
            mock_private_key.private_bytes.return_value = b"-----BEGIN PRIVATE KEY-----\nunencrypted-key\n-----END PRIVATE KEY-----"

            # Mock subprocess for reload command
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_subprocess.return_value = mock_result

            # Run the sync
            manager = CertSyncManager("/config/test.yaml")
            result = manager.sync_all_certificates()

            # Verify success - certificate should be refreshed
            assert result is True

            # Verify ACM was called to get new certificate
            mock_acm.describe_certificate.assert_called_once()
            mock_acm.export_certificate.assert_called_once()

            # Verify files were written (because certificate was expiring)
            assert (
                mock_file.call_count >= 3
            )  # Read existing + write new cert, key, chain

            # Verify reload command was executed
            mock_subprocess.assert_called_once()

    @patch("boto3.client")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_skip_sync_valid_certificate(
        self, mock_file, mock_exists, mock_boto3_client
    ):
        """Test that sync is skipped when existing certificate is still valid"""

        # Setup config
        config = {
            "aws": {"region": "us-east-1"},
            "certificates": [
                {
                    "name": "valid-cert",
                    "arn": "arn:aws:acm:us-east-1:123456789012:certificate/test",
                    "targets": [
                        {
                            "base_dir": "/etc/ssl",
                            "server_type": "nginx",
                            "passphrase": "",
                            "reload_command": "systemctl reload nginx",
                        }
                    ],
                }
            ],
        }

        # Mock existing valid certificate on disk (expires in 60 days)
        valid_cert_pem = self.create_test_certificate_pem(days_until_expiry=60)

        # Mock file system - certificate exists and is valid
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = valid_cert_pem

        # Mock boto3 ACM client
        mock_acm = MagicMock()
        mock_boto3_client.return_value = mock_acm
        mock_acm.describe_certificate.return_value = {}

        # Mock environment variable for expiry threshold
        with patch.dict(os.environ, {"DAYS_BEFORE_EXPIRY": "30"}):
            with patch("yaml.safe_load", return_value=config):
                manager = CertSyncManager("/config/test.yaml")
                result = manager.sync_all_certificates()

        # Verify success - but no actual sync was needed
        assert result is True

        # Verify ACM describe was called to validate ARN
        mock_acm.describe_certificate.assert_called_once()

        # Verify export was NOT called (certificate was already valid)
        mock_acm.export_certificate.assert_not_called()
