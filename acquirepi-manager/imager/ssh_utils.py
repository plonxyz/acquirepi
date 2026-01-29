"""
SSH key generation and management utilities for acquirepi agents.
"""
import os
import subprocess
from pathlib import Path
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# SSH keys directory
SSH_KEYS_DIR = Path(settings.BASE_DIR) / 'ssh_keys'


def ensure_ssh_keys_directory():
    """Ensure SSH keys directory exists with proper permissions."""
    SSH_KEYS_DIR.mkdir(mode=0o700, exist_ok=True)
    logger.info(f"SSH keys directory: {SSH_KEYS_DIR}")


def generate_ssh_key_pair(mac_address):
    """
    Generate an SSH key pair for an agent.

    Args:
        mac_address: MAC address of the agent (used as identifier)

    Returns:
        tuple: (private_key_path, public_key_content) or (None, None) on failure
    """
    ensure_ssh_keys_directory()

    # Sanitize MAC address for filename (replace colons with underscores)
    safe_mac = mac_address.replace(':', '_')
    key_name = f"{safe_mac}_rsa"
    private_key_path = SSH_KEYS_DIR / key_name
    public_key_path = SSH_KEYS_DIR / f"{key_name}.pub"

    # Check if key already exists
    if private_key_path.exists():
        logger.info(f"SSH key already exists for {mac_address}, reading existing key")
        try:
            with open(public_key_path, 'r') as f:
                public_key = f.read().strip()
            return str(private_key_path), public_key
        except FileNotFoundError:
            logger.warning(f"Public key missing for {mac_address}, regenerating")
            # Remove orphaned private key
            private_key_path.unlink(missing_ok=True)

    # Generate new SSH key pair
    logger.info(f"Generating SSH key pair for agent {mac_address}")

    try:
        # Generate ED25519 key (more secure and shorter than RSA)
        # Alternative: use 'rsa' with -b 4096 for RSA keys
        result = subprocess.run(
            [
                '/usr/bin/ssh-keygen',
                '-t', 'ed25519',
                '-f', str(private_key_path),
                '-N', '',  # No passphrase (required for automated access)
                '-C', f'acquirepi-manager-{mac_address}'
            ],
            capture_output=True,
            text=True,
            check=True
        )

        logger.info(f"SSH key pair generated successfully for {mac_address}")

        # Set secure permissions
        os.chmod(private_key_path, 0o600)
        os.chmod(public_key_path, 0o644)

        # Read public key
        with open(public_key_path, 'r') as f:
            public_key = f.read().strip()

        return str(private_key_path), public_key

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate SSH key for {mac_address}: {e.stderr}")
        return None, None
    except Exception as e:
        logger.error(f"Unexpected error generating SSH key for {mac_address}: {e}")
        return None, None


def get_public_key(mac_address):
    """
    Get the public key for an agent by MAC address.

    Args:
        mac_address: MAC address of the agent

    Returns:
        str: Public key content or None if not found
    """
    safe_mac = mac_address.replace(':', '_')
    public_key_path = SSH_KEYS_DIR / f"{safe_mac}_rsa.pub"

    try:
        with open(public_key_path, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        logger.warning(f"Public key not found for {mac_address}")
        return None


def delete_ssh_key_pair(mac_address):
    """
    Delete SSH key pair for an agent.

    Args:
        mac_address: MAC address of the agent

    Returns:
        bool: True if deleted successfully
    """
    safe_mac = mac_address.replace(':', '_')
    private_key_path = SSH_KEYS_DIR / f"{safe_mac}_rsa"
    public_key_path = SSH_KEYS_DIR / f"{safe_mac}_rsa.pub"

    success = True

    try:
        if private_key_path.exists():
            private_key_path.unlink()
            logger.info(f"Deleted private key for {mac_address}")
    except Exception as e:
        logger.error(f"Failed to delete private key for {mac_address}: {e}")
        success = False

    try:
        if public_key_path.exists():
            public_key_path.unlink()
            logger.info(f"Deleted public key for {mac_address}")
    except Exception as e:
        logger.error(f"Failed to delete public key for {mac_address}: {e}")
        success = False

    return success


def get_ssh_connection_command(agent):
    """
    Generate SSH connection command for an agent.

    Args:
        agent: Agent model instance

    Returns:
        list: SSH command as list of arguments
    """
    if not agent.ssh_key_path or not Path(agent.ssh_key_path).exists():
        logger.error(f"SSH key not found for agent {agent.mac_address}")
        return None

    return [
        'ssh',
        '-i', agent.ssh_key_path,
        '-o', 'StrictHostKeyChecking=no',  # Auto-accept host key (trust on first use)
        '-o', 'UserKnownHostsFile=/dev/null',  # Don't save to known_hosts
        f'{agent.ssh_username}@{agent.ip_address}'
    ]
