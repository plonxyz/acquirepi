#!/usr/bin/env python3
"""
acquirepi Agent Client
Discovers the manager server via mDNS and communicates with it.
This script should be deployed to /usr/local/bin on acquirepi devices.
"""

import os
import sys
import time
import json
import socket
import subprocess
import logging
import re
import requests
import yaml
import psutil
from zeroconf import ServiceBrowser, Zeroconf
from threading import Event, Thread
from pathlib import Path
from datetime import datetime, timedelta

# I2C LCD Display support - Direct I2C for Surenoo SCL1602M-YGY-I2C
try:
    import smbus
    LCD_AVAILABLE = True
except ImportError:
    LCD_AVAILABLE = False
    logger = logging.getLogger('acquirepi-agent')
    logger.warning("smbus library not available - display features disabled")

# Configuration
CONFIG_PATH = "/mnt/usb/Imager_config.yaml"
CONFIG_STICK_UUID = "937C-8BC2"  # UUID of the config USB stick
LOG_FILE = "/var/log/acquirepi-agent.log"
HEARTBEAT_INTERVAL = 5  # seconds
POLL_INTERVAL = 10  # seconds
MANAGER_SERVICE_TYPE = "_acquirepi._tcp.local."
DISK_WAIT_TIMEOUT = 300  # seconds (5 minutes) - max time to wait for disk
DISK_CHECK_INTERVAL = 5  # seconds - how often to check for disk

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('acquirepi-agent')


class LCDDisplayManager:
    """Manages I2C 1602 LCD display (Surenoo SCL1602M-YGY-I2C) for agent status."""

    # I2C Constants
    I2C_ADDR = 0x3e
    CTRL_CMD = 0x00   # Co=0, RS=0 for command
    CTRL_DATA = 0x40  # Co=0, RS=1 for data

    def __init__(self):
        self.bus = None
        self.enabled = False
        self.current_message = ""
        self.scroll_thread = None
        self.scroll_active = False

        if LCD_AVAILABLE:
            try:
                # Initialize I2C bus
                self.bus = smbus.SMBus(1)
                self._init_lcd()
                self.enabled = True
                self.clear()
                logger.info(f"LCD display initialized successfully at address 0x{self.I2C_ADDR:02x}")
            except Exception as e:
                logger.warning(f"Failed to initialize LCD: {e}")
                self.enabled = False

    def _lcd_cmd(self, cmd):
        """Send command to LCD"""
        if not self.enabled or not self.bus:
            return
        try:
            self.bus.write_i2c_block_data(self.I2C_ADDR, self.CTRL_CMD, [cmd])
            time.sleep(0.001)
        except:
            try:
                self.bus.write_byte_data(self.I2C_ADDR, self.CTRL_CMD, cmd)
                time.sleep(0.001)
            except Exception as e:
                logger.debug(f"LCD command error: {e}")

    def _lcd_data(self, data):
        """Send data to LCD"""
        if not self.enabled or not self.bus:
            return
        try:
            self.bus.write_i2c_block_data(self.I2C_ADDR, self.CTRL_DATA, [data])
            time.sleep(0.001)
        except:
            try:
                self.bus.write_byte_data(self.I2C_ADDR, self.CTRL_DATA, data)
                time.sleep(0.001)
            except Exception as e:
                logger.debug(f"LCD data error: {e}")

    def _init_lcd(self):
        """Initialize the LCD display"""
        time.sleep(0.05)  # Wait for LCD to power up
        self._lcd_cmd(0x38)  # Function set: 8-bit, 2 lines, 5x8 dots
        time.sleep(0.005)
        self._lcd_cmd(0x0C)  # Display on, cursor off, blink off
        time.sleep(0.005)
        self._lcd_cmd(0x01)  # Clear display
        time.sleep(0.002)
        self._lcd_cmd(0x06)  # Entry mode: increment, no shift
        time.sleep(0.001)

    def _set_cursor(self, row, col):
        """Set cursor position (row: 0-1, col: 0-15)"""
        if not self.enabled:
            return
        row_offsets = [0x00, 0x40]
        if row < 2 and col < 16:
            self._lcd_cmd(0x80 | (col + row_offsets[row]))

    def clear(self):
        """Clear the LCD display."""
        if not self.enabled:
            return
        try:
            self._lcd_cmd(0x01)
            time.sleep(0.002)
        except Exception as e:
            logger.debug(f"LCD clear error: {e}")

    def _write_string(self, text, row=0):
        """Write string to specified row"""
        if not self.enabled:
            return
        self._set_cursor(row, 0)
        for char in text[:16].ljust(16):  # Pad to 16 chars
            self._lcd_data(ord(char))

    def display(self, line1, line2=""):
        """Display static text on LCD (no scrolling)."""
        if not self.enabled:
            return

        try:
            # Stop any active scrolling
            self.scroll_active = False

            self.clear()
            self._write_string(line1, 0)
            if line2:
                self._write_string(line2, 1)

            self.current_message = f"{line1}\n{line2}"
        except Exception as e:
            logger.debug(f"LCD display error: {e}")

    def display_scrolling(self, line1, line2):
        """Display text with scrolling if it exceeds 16 characters."""
        if not self.enabled:
            return

        # Stop any previous scrolling
        self.scroll_active = False
        if self.scroll_thread and self.scroll_thread.is_alive():
            self.scroll_thread.join(timeout=1)

        # Start new scrolling thread
        self.scroll_active = True
        self.scroll_thread = Thread(target=self._scroll_text, args=(line1, line2), daemon=True)
        self.scroll_thread.start()

    def _scroll_text(self, line1, line2):
        """Internal method to handle text scrolling."""
        try:
            while self.scroll_active:
                # Display line 1
                if len(line1) > 16:
                    # Scroll line 1
                    for i in range(len(line1) - 15):
                        if not self.scroll_active:
                            return
                        self._write_string(line1[i:i+16], 0)
                        time.sleep(0.3)
                    time.sleep(1)
                else:
                    self._write_string(line1, 0)

                # Display line 2
                if len(line2) > 16:
                    # Scroll line 2
                    for i in range(len(line2) - 15):
                        if not self.scroll_active:
                            return
                        self._write_string(line2[i:i+16], 1)
                        time.sleep(0.3)
                    time.sleep(1)
                else:
                    self._write_string(line2, 1)

                time.sleep(2)  # Pause before restarting scroll
        except Exception as e:
            logger.debug(f"LCD scroll error: {e}")

    def show_progress_bar(self, progress, line1=""):
        """Show progress bar on line 2, optional text on line 1."""
        if not self.enabled:
            return

        try:
            self.scroll_active = False

            # Calculate progress bar (14 characters wide)
            bar_width = 14
            filled = int((progress / 100.0) * bar_width)
            bar = chr(255) * filled + "-" * (bar_width - filled)

            # Line 1: custom text or progress percentage
            if line1:
                self._write_string(line1, 0)
            else:
                self._write_string(f"Progress: {int(progress):3d}%", 0)

            # Line 2: progress bar
            self._write_string(f"[{bar}]", 1)
        except Exception as e:
            logger.debug(f"LCD progress error: {e}")

    def show_job_progress(self, progress, speed="", eta=""):
        """Show detailed job progress with speed and ETA."""
        if not self.enabled:
            return

        try:
            self.scroll_active = False

            # Line 1: Progress percentage and speed
            line1 = f"{int(progress):3d}% {speed}".ljust(16)[:16]

            # Line 2: Progress bar or ETA
            if eta:
                # Show ETA instead of bar for first few seconds
                line2 = f"ETA: {eta}".ljust(16)[:16]
            else:
                # Show progress bar
                bar_width = 16
                filled = int((progress / 100.0) * bar_width)
                line2 = chr(255) * filled + "-" * (bar_width - filled)

            self._write_string(line1, 0)
            self._write_string(line2, 1)
        except Exception as e:
            logger.debug(f"LCD job progress error: {e}")

    def show_status(self, status, detail=""):
        """Show agent status."""
        status_icons = {
            'starting': chr(126),     # ~
            'online': chr(4),         # ♦
            'imaging': chr(255),      # █
            'error': chr(88),         # X
            'waiting': chr(46),       # .
        }

        icon = status_icons.get(status, ' ')
        line1 = f"{icon} {status.upper()}".ljust(16)[:16]
        self.display(line1, detail[:16])

    def close(self):
        """Clean up LCD resources."""
        self.scroll_active = False
        if self.enabled:
            try:
                self.clear()
                if self.bus:
                    self.bus.close()
            except Exception as e:
                logger.debug(f"LCD close error: {e}")


class ManagerDiscoveryListener:
    """Listener for mDNS service discovery."""

    def __init__(self):
        self.manager_found = Event()
        self.manager_address = None
        self.manager_port = None

    def remove_service(self, zeroconf, service_type, name):
        """Called when a service is removed."""
        logger.info(f"Service {name} removed")

    def add_service(self, zeroconf, service_type, name):
        """Called when a service is discovered."""
        info = zeroconf.get_service_info(service_type, name)
        if info:
            address = socket.inet_ntoa(info.addresses[0])
            port = info.port
            logger.info(f"Discovered acquirepi manager at {address}:{port}")
            self.manager_address = address
            self.manager_port = port
            self.manager_found.set()

    def update_service(self, zeroconf, service_type, name):
        """Called when a service is updated."""
        pass


class Agent:
    """acquirepi Agent that communicates with the manager."""

    def __init__(self):
        self.manager_url = None
        self.agent_id = None
        self.mac_address = self._get_mac_address()
        self.hostname = socket.gethostname()
        self.ip_address = self._get_ip_address()
        self.current_job = None
        self.pre_imaging_smart_data = None  # Collected before imaging starts
        self.lcd = LCDDisplayManager()  # Initialize LCD display
        self.job_start_time = None
        self.last_progress = 0
        self.last_progress_time = None

        # LED blinking control
        self._led_blink_active = False
        self._led_blink_thread = None

        # Prime psutil CPU monitoring (first call initializes internal state)
        psutil.cpu_percent(interval=None)

    # LED Control Methods (Pi 5 ACT LED is active-low: 1=off, 0=on)
    LED_PATH = "/sys/class/leds/ACT/brightness"
    LED_TRIGGER_PATH = "/sys/class/leds/ACT/trigger"

    def _led_control(self, state):
        """Set LED state. state=0 means ON, state=1 means OFF (active-low on Pi 5)."""
        try:
            # Disable trigger first to prevent it from overriding brightness
            subprocess.run(['sudo', 'tee', self.LED_TRIGGER_PATH],
                         input=b'none', capture_output=True)
            subprocess.run(['sudo', 'tee', self.LED_PATH],
                         input=str(state).encode(), capture_output=True)
        except Exception as e:
            logger.debug(f"LED control failed: {e}")

    def _led_blink_loop(self, interval=0.1):
        """Background thread for LED blinking."""
        while self._led_blink_active:
            self._led_control(0)  # ON
            time.sleep(interval)
            self._led_control(1)  # OFF
            time.sleep(interval)

    def _led_start_blink(self, interval=0.1):
        """Start LED blinking in background thread."""
        if self._led_blink_thread and self._led_blink_thread.is_alive():
            return  # Already blinking
        self._led_blink_active = True
        self._led_blink_thread = Thread(target=self._led_blink_loop, args=(interval,), daemon=True)
        self._led_blink_thread.start()
        logger.debug("LED blinking started")

    def _led_stop_blink(self):
        """Stop LED blinking."""
        self._led_blink_active = False
        if self._led_blink_thread:
            self._led_blink_thread.join(timeout=1)
            self._led_blink_thread = None
        self._led_control(1)  # Turn off
        logger.debug("LED blinking stopped")

    def _get_mac_address(self):
        """Get the MAC address of the primary network interface."""
        try:
            # Try eth0 first
            with open('/sys/class/net/eth0/address', 'r') as f:
                return f.read().strip()
        except FileNotFoundError:
            # Fall back to wlan0
            try:
                with open('/sys/class/net/wlan0/address', 'r') as f:
                    return f.read().strip()
            except FileNotFoundError:
                logger.error("Could not determine MAC address")
                return "00:00:00:00:00:00"

    def _get_ip_address(self):
        """Get the IP address of the system."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _get_hardware_info(self):
        """Get hardware information."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Model'):
                        return line.split(':')[1].strip()
        except Exception:
            pass
        return "Raspberry Pi"

    def _get_serial_number(self):
        """Get the device serial number."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('Serial'):
                        return line.split(':')[1].strip()
        except Exception:
            pass
        return None

    def check_usb_config_stick(self):
        """Check for config USB stick and mount if found."""
        try:
            # Check if config stick UUID exists
            result = subprocess.run(['blkid', '-U', CONFIG_STICK_UUID],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                device = result.stdout.strip()
                logger.info(f"Found config stick at {device}")

                # Check if already mounted
                if not os.path.ismount('/mnt/usb'):
                    # Create mount point and mount
                    os.makedirs('/mnt/usb', exist_ok=True)
                    mount_result = subprocess.run(['sudo', 'mount', device, '/mnt/usb'],
                                                 capture_output=True, text=True)
                    if mount_result.returncode == 0:
                        logger.info("Config stick mounted at /mnt/usb")
                    else:
                        logger.error(f"Failed to mount config stick: {mount_result.stderr}")
                        return False

                # Check if config file exists
                if os.path.exists(CONFIG_PATH):
                    logger.info(f"Found config file at {CONFIG_PATH}")
                    return True
                else:
                    logger.warning(f"Config stick mounted but no {CONFIG_PATH} found")
                    return False
        except Exception as e:
            logger.debug(f"Config stick check failed: {e}")

        return False

    def discover_manager(self, timeout=5, max_attempts=10):
        """Discover the manager server via mDNS or use hardcoded URL."""
        self.lcd.display("Finding", "Manager...")

        # Check for USB config stick FIRST for standalone/airgap mode
        # This takes priority over manager discovery (enables airgap operation)
        if self.check_usb_config_stick():
            logger.info("USB config stick detected - entering standalone mode")
            self.lcd.display("Standalone Mode", "USB Config")
            self.manager_url = None  # No manager in standalone mode
            time.sleep(2)
            return True

        # Check for hardcoded manager URL in environment
        hardcoded_url = os.environ.get('MANAGER_URL')
        if hardcoded_url:
            logger.info(f"Using hardcoded manager URL: {hardcoded_url}")
            self.manager_url = hardcoded_url
            self.lcd.display("Manager Found", hardcoded_url.split('//')[-1][:16])
            time.sleep(2)
            return True

        logger.info(f"Starting mDNS discovery for acquirepi manager ({max_attempts} attempts, {timeout}s each)...")

        # Retry loop for mDNS discovery
        for attempt in range(1, max_attempts + 1):
            logger.info(f"Discovery attempt {attempt}/{max_attempts}...")
            self.lcd.display("Finding Mgr", f"Attempt {attempt}/{max_attempts}")

            zeroconf = Zeroconf()
            listener = ManagerDiscoveryListener()
            browser = ServiceBrowser(zeroconf, MANAGER_SERVICE_TYPE, listener)

            # Wait for discovery
            if listener.manager_found.wait(timeout=timeout):
                self.manager_url = f"http://{listener.manager_address}:{listener.manager_port}"
                logger.info(f"Manager found at {self.manager_url}")
                self.lcd.display("Manager Found", f"{listener.manager_address}")
                zeroconf.close()
                time.sleep(2)
                return True
            else:
                zeroconf.close()
                if attempt < max_attempts:
                    logger.info(f"Manager not found, retrying...")

        logger.error(f"Manager not found after {max_attempts} attempts")

        # Fallback URL for Wireguard/remote scenarios (set by installer via sed)
        fallback_url = ""

        if fallback_url:
            logger.info(f"Trying fallback URL: {fallback_url}")
            self.manager_url = fallback_url
            # Extract hostname/IP from URL for display
            fallback_host = fallback_url.replace("http://", "").replace("https://", "").split(":")[0]
            self.lcd.display("Using Fallback", fallback_host)
            time.sleep(2)
            return True
        else:
            logger.error("No manager found and no USB config stick - unable to operate")
            self.lcd.display("No Manager", "No Config Stick")
            return False

    def register(self):
        """Register this agent with the manager."""
        logger.info("Registering with manager...")
        self.lcd.display("Registering...", self.hostname)

        data = {
            'hostname': self.hostname,
            'mac_address': self.mac_address,
            'ip_address': self.ip_address,
            'hardware_model': self._get_hardware_info(),
            'serial_number': self._get_serial_number(),
            'supports_disk': True,
            'supports_nfs': True,
        }

        try:
            response = requests.post(
                f"{self.manager_url}/api/agents/register/",
                json=data,
                timeout=10
            )
            response.raise_for_status()

            result = response.json()
            self.agent_id = result['agent_id']
            logger.info(f"Registered successfully. Agent ID: {self.agent_id}, Status: {result['status']}")

            if result['is_approved']:
                self.lcd.show_status("approved")
                # Notify manager to cleanup any orphaned in-progress jobs from previous runs
                self._cleanup_orphaned_jobs()
            else:
                self.lcd.show_status("pending")
            time.sleep(2)

            return result['is_approved']

        except Exception as e:
            logger.error(f"Registration failed: {e}")
            self.lcd.display("Registration", "Failed!")
            time.sleep(2)
            return False

    def _cleanup_orphaned_jobs(self):
        """Notify manager to fail any in-progress jobs that were orphaned by agent restart."""
        if not self.agent_id:
            return

        try:
            logger.info("Checking for orphaned in-progress jobs from previous agent run...")
            response = requests.post(
                f"{self.manager_url}/api/agents/{self.agent_id}/cleanup_orphaned_jobs/",
                json={'reason': 'Agent restarted - job was interrupted'},
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                failed_count = result.get('failed_count', 0)
                if failed_count > 0:
                    logger.warning(f"Cleaned up {failed_count} orphaned job(s) from previous run")
                    self._log_to_manager('warning', f"Agent restart: {failed_count} orphaned job(s) marked as failed")
                else:
                    logger.info("No orphaned jobs found")
            else:
                logger.debug(f"Orphan cleanup endpoint returned {response.status_code}")

        except Exception as e:
            logger.debug(f"Could not cleanup orphaned jobs: {e}")

    def _log_to_manager(self, level, message):
        """Send a log message to manager (for agent-level events, not job-specific)."""
        try:
            requests.post(
                f"{self.manager_url}/api/agents/{self.agent_id}/log/",
                json={'level': level, 'message': message},
                timeout=5
            )
        except:
            pass  # Non-critical

    def setup_ssh_key(self):
        """Retrieve and install SSH public key from manager."""
        logger.info("Retrieving SSH key from manager...")

        try:
            response = requests.get(
                f"{self.manager_url}/api/agents/get_ssh_key/",
                params={'mac_address': self.mac_address},
                timeout=10
            )
            response.raise_for_status()

            result = response.json()
            if result.get('has_key'):
                public_key = result['public_key']
                self._install_ssh_key(public_key)
                logger.info("SSH key installed successfully")
                return True
            else:
                logger.warning("No SSH key available from manager yet")
                return False

        except Exception as e:
            logger.error(f"Failed to retrieve SSH key: {e}")
            return False

    def _install_ssh_key(self, public_key):
        """Install SSH public key to authorized_keys."""
        # Install to pi user's home directory (not service user which might be root)
        import pwd
        target_user = 'pi'
        try:
            pw_record = pwd.getpwnam(target_user)
            home_dir = Path(pw_record.pw_dir)
            uid = pw_record.pw_uid
            gid = pw_record.pw_gid
        except KeyError:
            # Fall back to current user if 'pi' doesn't exist
            home_dir = Path.home()
            uid = os.getuid()
            gid = os.getgid()
            logger.warning(f"User '{target_user}' not found, installing to {home_dir}")

        ssh_dir = home_dir / '.ssh'
        authorized_keys = ssh_dir / 'authorized_keys'

        # Create .ssh directory if it doesn't exist
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        # Fix ownership (agent runs as root, but files must be owned by target user)
        os.chown(ssh_dir, uid, gid)

        # Read existing keys
        existing_keys = []
        if authorized_keys.exists():
            with open(authorized_keys, 'r') as f:
                existing_keys = f.read().splitlines()

        # Check if key already exists
        if public_key in existing_keys:
            logger.info("SSH key already in authorized_keys")
        else:
            # Append new key
            with open(authorized_keys, 'a') as f:
                if existing_keys and not existing_keys[-1] == '':
                    f.write('\n')
                f.write(public_key + '\n')
            logger.info("SSH key added to authorized_keys")

        # Always ensure correct permissions and ownership (agent runs as root)
        os.chmod(authorized_keys, 0o600)
        os.chown(authorized_keys, uid, gid)

    def _get_resource_stats(self):
        """Get current resource utilization stats."""
        try:
            # CPU usage - sample over 1 second for accurate reading
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_total_mb = memory.total // (1024 * 1024)
            memory_used_mb = memory.used // (1024 * 1024)

            # Disk usage (check /mnt/usb first, fallback to root)
            disk_path = '/mnt/usb' if os.path.exists('/mnt/usb') else '/'
            disk = psutil.disk_usage(disk_path)
            disk_percent = disk.percent
            disk_total_gb = disk.total // (1024 ** 3)
            disk_used_gb = disk.used // (1024 ** 3)

            # Temperature (Raspberry Pi specific)
            temp_celsius = None
            try:
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp_celsius = float(f.read().strip()) / 1000.0
            except Exception:
                pass

            # Network stats
            net_io = psutil.net_io_counters()
            network_sent_mb = net_io.bytes_sent // (1024 * 1024)
            network_recv_mb = net_io.bytes_recv // (1024 * 1024)

            # Detect available disks (cache for 30 seconds)
            current_time = time.time()
            if not hasattr(self, '_disk_cache_time') or (current_time - self._disk_cache_time) > 30:
                self._available_disks = self.detect_available_disks()
                self._disk_cache_time = current_time
                logger.debug(f"Refreshed disk cache: {len(self._available_disks)} disks")

            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'memory_total_mb': memory_total_mb,
                'memory_used_mb': memory_used_mb,
                'disk_percent': disk_percent,
                'disk_total_gb': disk_total_gb,
                'disk_used_gb': disk_used_gb,
                'temperature_celsius': temp_celsius,
                'network_sent_mb': network_sent_mb,
                'network_recv_mb': network_recv_mb,
                'available_disks': getattr(self, '_available_disks', []),
            }
        except Exception as e:
            logger.error(f"Failed to get resource stats: {e}")
            return {}

    def heartbeat(self):
        """Send heartbeat to manager with resource stats."""
        if not self.agent_id:
            return

        try:
            # Get resource stats
            stats = self._get_resource_stats()

            response = requests.post(
                f"{self.manager_url}/api/agents/{self.agent_id}/heartbeat/",
                json=stats,
                timeout=5
            )
            response.raise_for_status()
            logger.debug("Heartbeat sent successfully")

            # Check for pending commands from manager
            result = response.json()
            if result.get('pending_command'):
                command = result['pending_command']
                logger.info(f"Received command from manager: {command}")
                self.execute_command(command)

        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")

    def execute_command(self, command):
        """Execute a command received from the manager."""
        logger.info(f"Executing command: {command}")

        if command == 'reboot':
            logger.warning("Reboot command received - system will reboot in 3 seconds")
            subprocess.run(['sudo', 'shutdown', '-r', '+0', 'Reboot requested by acquirepi Manager'])
        elif command == 'shutdown':
            logger.warning("Shutdown command received - system will shutdown in 3 seconds")
            subprocess.run(['sudo', 'shutdown', '-h', '+0', 'Shutdown requested by acquirepi Manager'])
        else:
            logger.warning(f"Unknown command received: {command}")

    def check_for_jobs(self):
        """Check if there are pending jobs for this agent."""
        try:
            response = requests.get(
                f"{self.manager_url}/api/jobs/pending/",
                params={'mac_address': self.mac_address},
                timeout=10
            )
            response.raise_for_status()

            result = response.json()
            if result['has_job']:
                logger.info(f"New job found: {result['job_id']}")
                return result
            return None

        except Exception as e:
            logger.error(f"Failed to check for jobs: {e}")
            return None

    def execute_job(self, job_info):
        """Execute an imaging job."""
        job_id = job_info['job_id']
        config = job_info['config']

        logger.info(f"Starting job {job_id}")
        self.current_job = job_id

        # Display job information with scrolling
        case_num = config.get('imager-config', {}).get('case_number', 'N/A')
        evidence_num = config.get('imager-config', {}).get('evidence_number', 'N/A')
        job_text = f"Job {job_id}: Case {case_num} Evidence {evidence_num}"
        self.lcd.display_scrolling(job_text, "Initializing...")

        # Mark job as started
        try:
            requests.post(
                f"{self.manager_url}/api/jobs/{job_id}/start/",
                timeout=5
            )
        except Exception as e:
            logger.error(f"Failed to mark job as started: {e}")

        # Check if this is a mobile device extraction job
        mobile_extraction = job_info.get('mobile_extraction')
        if mobile_extraction:
            logger.info("Detected mobile device extraction job")
            self.lcd.display("Mobile Device", "Extraction")
            time.sleep(1)
            self._execute_mobile_extraction(job_info)
            return

        # Write config to file
        try:
            os.makedirs('/mnt/usb', exist_ok=True)
            with open(CONFIG_PATH, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
            logger.info(f"Config written to {CONFIG_PATH}")
        except Exception as e:
            logger.error(f"Failed to write config: {e}")
            self._fail_job(job_id, str(e))
            self.lcd.display("Job Failed!", str(e)[:16])
            time.sleep(3)
            return

        # Check if source device is specified in config (from manager)
        source_device = config.get('system', {}).get('source_device')
        if source_device:
            logger.info(f"Using source device from job config: {source_device}")
            self._log_job(job_id, 'info', f"Source device specified by manager: {source_device}")
            # Verify the device exists
            if not os.path.exists(source_device):
                logger.warning(f"Specified source device {source_device} not found, falling back to auto-detection")
                source_device = None

        # If no source device specified, wait for it to be connected (auto-detect)
        if not source_device:
            logger.info("Checking for source device...")
            self.lcd.display("Waiting for", "source device...")
            source_device = self._wait_for_source_device(job_id)

        if not source_device:
            # Timeout - no device detected
            error = "Source device not detected within timeout period"
            logger.error(error)
            self._fail_job(job_id, error)
            self.lcd.display("Device timeout!", "Check connection")
            time.sleep(3)
            return

        # Device detected
        self.lcd.display("Device detected", source_device[:16])
        time.sleep(1)

        # Get upload method from config
        upload_method = config['system']['upload_method']

        # Check disk capacity for disk-to-disk imaging
        if upload_method == 'disk':
            try:
                self.lcd.display("Checking", "disk capacity...")
                self._log_job(job_id, 'info', "Checking destination disk capacity")

                # Get source device size
                source_size_bytes = self._get_device_size(source_device)
                if source_size_bytes:
                    source_size_gb = source_size_bytes / (1024 ** 3)
                    logger.info(f"Source device size: {source_size_gb:.1f} GB")

                    # Find destination device (exFAT formatted disk that's not the source)
                    dest_device, dest_size_bytes = self._find_destination_device(source_device)
                    if dest_device and dest_size_bytes:
                        dest_size_gb = dest_size_bytes / (1024 ** 3)
                        # E01 compression typically achieves 30-50% compression, but we need to be safe
                        # Use 70% of source size as estimate (assumes some compression)
                        estimated_image_size = source_size_bytes * 0.7
                        estimated_gb = estimated_image_size / (1024 ** 3)

                        logger.info(f"Destination device: {dest_device}, size: {dest_size_gb:.1f} GB")
                        self._log_job(job_id, 'info', f"Source: {source_size_gb:.1f} GB, Destination: {dest_size_gb:.1f} GB available")
                        self._log_job(job_id, 'info', f"Estimated E01 image size (with compression): ~{estimated_gb:.1f} GB")

                        if dest_size_bytes < estimated_image_size:
                            error_msg = f"Destination disk too small. Available: {dest_size_gb:.1f} GB, Estimated E01 size: ~{estimated_gb:.1f} GB (source: {source_size_gb:.1f} GB)"
                            logger.error(error_msg)
                            self._log_job(job_id, 'error', error_msg)
                            self._fail_job(job_id, error_msg)
                            self.lcd.display("Disk too small!", f"Need {estimated_gb:.0f}GB")
                            time.sleep(3)
                            return

                        self._log_job(job_id, 'info', "Disk capacity check passed")
                    else:
                        logger.warning("Could not find destination device for capacity check")
                        self._log_job(job_id, 'warning', "Could not verify destination capacity - proceeding anyway")
                else:
                    logger.warning("Could not determine source device size")
                    self._log_job(job_id, 'warning', "Could not determine source size - proceeding anyway")
            except Exception as e:
                logger.warning(f"Disk capacity check failed: {e}")
                self._log_job(job_id, 'warning', f"Disk capacity check failed: {e} - proceeding anyway")

        # Collect SMART data BEFORE imaging (forensic best practice)
        # This captures the device state as received, before hours of read activity
        logger.info("Collecting SMART data from source device (pre-imaging)...")
        self.lcd.display("Collecting", "SMART data...")
        self.pre_imaging_smart_data = self._auto_detect_and_collect_smart()
        if self.pre_imaging_smart_data:
            logger.info("SMART data collected successfully before imaging")
            self._log_job(job_id, 'info', "SMART data collected from source device")
        else:
            logger.warning("No SMART data collected, continuing anyway")
            self._log_job(job_id, 'warning', "Could not collect SMART data from device")

        # Execute the appropriate imaging script
        self.lcd.display("Starting", f"{upload_method} imaging")
        time.sleep(1)
        script_map = {
            'disk': '/usr/local/bin/disk_mount.sh',
            'nfs': '/usr/local/bin/nfs-imager.sh',
        }

        script = script_map.get(upload_method)
        if not script:
            error = f"Unknown upload method: {upload_method}"
            logger.error(error)
            self._fail_job(job_id, error)
            return

        # Log job start
        self._log_job(job_id, 'info', f"Starting {upload_method} imaging job")

        try:
            # Run the imaging script and monitor output
            process = subprocess.Popen(
                [script],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1
            )

            # Monitor output for progress and check for cancellation
            last_cancel_check = time.time()
            cancel_check_interval = 5  # Check every 5 seconds

            for line in process.stdout:
                logger.info(line.strip())
                self._log_job(job_id, 'info', line.strip())

                # Check for cancellation periodically
                if time.time() - last_cancel_check > cancel_check_interval:
                    if self._check_job_cancelled(job_id):
                        logger.warning(f"Job {job_id} has been cancelled - terminating imaging process")
                        self._log_job(job_id, 'warning', "Job cancelled by user - stopping imaging")
                        self.lcd.display("Job Cancelled!", "Stopping...")

                        # Kill the imaging process
                        process.terminate()
                        time.sleep(2)
                        if process.poll() is None:
                            process.kill()

                        # Clean up and exit
                        self.lcd.display("Job Cancelled", "Cleanup complete")
                        time.sleep(2)
                        return
                    last_cancel_check = time.time()

                # Parse progress from ewfacquire output
                progress_match = re.search(r'Status: at (\d+)%', line)
                if progress_match:
                    percentage = float(progress_match.group(1))

                    # Extract additional info
                    acquired_match = re.search(r'acquired (\d+\.?\d*) GiB', line)
                    total_match = re.search(r'of total (\d+\.?\d*) GiB', line)
                    speed_match = re.search(r'(\d+\.?\d*) MiB/s', line)

                    acquired_bytes = int(float(acquired_match.group(1)) * 1024**3) if acquired_match else None
                    total_bytes = int(float(total_match.group(1)) * 1024**3) if total_match else None
                    speed = speed_match.group(0) if speed_match else None

                    # Check if job was cancelled via progress response
                    if self._update_progress(job_id, percentage, acquired_bytes, total_bytes, speed):
                        logger.warning(f"Job {job_id} cancelled (detected via progress update)")
                        self._log_job(job_id, 'warning', "Job cancelled by user - stopping imaging")
                        self.lcd.display("Job Cancelled!", "Stopping...")
                        process.terminate()
                        time.sleep(2)
                        if process.poll() is None:
                            process.kill()
                        self.lcd.display("Job Cancelled", "Cleanup complete")
                        time.sleep(2)
                        return

            # Wait for process to complete
            return_code = process.wait()

            if return_code == 0:
                logger.info(f"Job {job_id} acquisition completed successfully")
                self.lcd.display("Acquisition", "Complete!")
                time.sleep(1)

                # Post-acquisition verification removed - ewfacquire already verifies hashes during imaging
                # verification_results = self._perform_post_acquisition_verification(job_id, upload_method)

                # Complete job with verification results
                self._complete_job(job_id, None)
                self.lcd.display("Job Complete!", "Ready for next")
                time.sleep(2)
            else:
                error = f"Imaging script exited with code {return_code}"
                logger.error(error)
                self._fail_job(job_id, error)
                self.lcd.display("Job Failed!", f"Error: {return_code}")
                time.sleep(3)

        except Exception as e:
            logger.error(f"Job execution failed: {e}")
            self._fail_job(job_id, str(e))
            self.lcd.display("Job Failed!", str(e)[:16])
            time.sleep(3)

        finally:
            self.current_job = None

    def _update_progress(self, job_id, percentage, acquired_bytes=None, total_bytes=None, speed=None):
        """Update job progress. Returns True if job was cancelled."""
        data = {
            'job_id': job_id,
            'progress_percentage': percentage,
        }
        if acquired_bytes is not None:
            data['acquired_bytes'] = acquired_bytes
        if total_bytes is not None:
            data['total_bytes'] = total_bytes
        if speed is not None:
            data['transfer_speed'] = speed

        # Calculate ETA
        eta_str = ""
        if acquired_bytes and total_bytes and speed:
            try:
                # Extract speed value (e.g., "150.5 MiB/s" -> 150.5)
                speed_value = float(speed.split()[0]) if isinstance(speed, str) else speed
                remaining_bytes = total_bytes - acquired_bytes
                remaining_mb = remaining_bytes / (1024 * 1024)
                eta_seconds = remaining_mb / speed_value if speed_value > 0 else 0

                # Format ETA
                if eta_seconds > 3600:
                    eta_str = f"{int(eta_seconds/3600)}h{int((eta_seconds%3600)/60)}m"
                elif eta_seconds > 60:
                    eta_str = f"{int(eta_seconds/60)}m{int(eta_seconds%60)}s"
                else:
                    eta_str = f"{int(eta_seconds)}s"
            except:
                eta_str = ""

        # Update LCD with progress bar and info
        speed_str = speed if speed else ""
        self.lcd.show_job_progress(percentage, speed_str, eta_str)

        try:
            response = requests.post(
                f"{self.manager_url}/api/jobs/{job_id}/progress/",
                json=data,
                timeout=5
            )
            # Also send heartbeat with current resource stats during job execution
            self.heartbeat()

            # Check if job was cancelled
            if response.status_code == 200:
                resp_data = response.json()
                if resp_data.get('is_cancelled', False):
                    logger.warning(f"Job {job_id} was cancelled (detected via progress response)")
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to update progress: {e}")
            return False

    def _perform_post_acquisition_verification(self, job_id, upload_method):
        """
        Perform post-acquisition verification before unmounting storage.
        This verifies the image integrity while it's still accessible.
        """
        logger.info("Starting post-acquisition verification")
        self.lcd.display("Verifying", "image integrity")
        self._log_job(job_id, 'info', "=" * 60)
        self._log_job(job_id, 'info', "POST-ACQUISITION VERIFICATION")
        self._log_job(job_id, 'info', "=" * 60)

        # Skip post-verification for disk mode - destination is unmounted after imaging
        if upload_method == 'disk':
            self._log_job(job_id, 'info', "Post-acquisition verification skipped for disk-to-disk imaging")
            self._log_job(job_id, 'info', "Destination device is unmounted after imaging completes")
            self._log_job(job_id, 'info', "Hash verification was performed during acquisition by ewfacquire")
            logger.info("Skipping post-verification for disk mode")
            return {}


        verification_results = {}

        try:
            # Read completion file to get image path
            completion_file = '/tmp/imaging_completion.json'
            if not os.path.exists(completion_file):
                logger.warning(f"Completion file not found: {completion_file}")
                self._log_job(job_id, 'warning', "Cannot verify - completion file not found")
                return verification_results

            with open(completion_file, 'r') as f:
                completion_data = json.load(f)

            image_path = completion_data.get('output_path')
            if not image_path:
                logger.warning("No image path in completion data")
                self._log_job(job_id, 'warning', "Cannot verify - no image path provided")
                return verification_results

            # For NFS/S3, the image is at the remote location
            # For disk, it's at /mnt/usb
            # The completion file should have the full path

            # For NFS uploads, the share may have been unmounted already
            # We need to check and remount if necessary for verification
            nfs_remounted = False
            if upload_method == 'nfs' and '/mnt/nfs-share' in image_path:
                if not os.path.exists(image_path):
                    # Try to remount NFS silently (without logging intermediate steps)
                    try:
                        import yaml
                        config_file = '/mnt/usb/Imager_config.yaml'
                        if os.path.exists(config_file):
                            with open(config_file, 'r') as f:
                                config = yaml.safe_load(f)

                            nfs_server = config.get('system', {}).get('nfs-config', {}).get('nfs-server')
                            nfs_share = config.get('system', {}).get('nfs-config', {}).get('nfs-share')

                            if nfs_server and nfs_share:
                                # Create mount point if needed
                                os.makedirs('/mnt/nfs-share', exist_ok=True)

                                # Mount NFS
                                mount_cmd = ['sudo', 'mount', '-t', 'nfs', f'{nfs_server}:{nfs_share}', '/mnt/nfs-share']
                                result = subprocess.run(mount_cmd, capture_output=True, text=True, timeout=30)

                                if result.returncode == 0:
                                    nfs_remounted = True
                                    logger.debug("Remounted NFS share for post-verification")
                    except Exception as e:
                        logger.debug(f"Could not remount NFS for verification: {e}")

            # Check if image file exists
            if not os.path.exists(image_path):
                # Try to find .E01 file in expected locations
                possible_paths = [
                    image_path,
                    f"/mnt/nfs-share/{os.path.basename(image_path)}",
                    f"/mnt/usb/{os.path.basename(image_path)}",
                ]

                image_found = False
                for path in possible_paths:
                    if os.path.exists(path):
                        image_path = path
                        image_found = True
                        logger.info(f"Found image at: {image_path}")
                        break

                if not image_found:
                    # For NFS, this is expected - the imaging script unmounted the share
                    # Hash verification was already completed during imaging
                    if upload_method == 'nfs':
                        logger.info(f"Image at remote location (NFS share unmounted after transfer)")
                        self._log_job(job_id, 'info', "Post-acquisition verification skipped - image at remote NFS location (hashes verified during imaging)")
                    else:
                        logger.warning(f"Image file not accessible for verification: {image_path}")
                        self._log_job(job_id, 'warning', f"Image not accessible at: {image_path}")

                    # Unmount NFS if we remounted it
                    if nfs_remounted:
                        try:
                            subprocess.run(['sudo', 'umount', '/mnt/nfs-share'], timeout=10)
                        except:
                            pass

                    return verification_results

            # Perform integrity verification using ewfverify
            logger.info(f"Verifying image: {image_path}")
            verification_results = self._verify_image_integrity(job_id, image_path)

            # Log summary
            if verification_results.get('verification_passed'):
                self._log_job(job_id, 'info', "=" * 60)
                self._log_job(job_id, 'info', "✓ POST-ACQUISITION VERIFICATION PASSED")
                self._log_job(job_id, 'info', "=" * 60)
                self.lcd.display("Verification", chr(0b11111111) + " PASSED " + chr(0b11111111))
                time.sleep(2)
            elif verification_results.get('verification_passed') is False:
                self._log_job(job_id, 'error', "=" * 60)
                self._log_job(job_id, 'error', "✗ POST-ACQUISITION VERIFICATION FAILED")
                self._log_job(job_id, 'error', "=" * 60)
                self.lcd.display("Verification", "X FAILED X")
                time.sleep(3)

            # Unmount NFS if we remounted it for verification
            if nfs_remounted:
                try:
                    logger.info("Unmounting NFS share after verification")
                    subprocess.run(['sudo', 'umount', '/mnt/nfs-share'], timeout=10)
                    self._log_job(job_id, 'info', "NFS share unmounted after verification")
                except Exception as umount_error:
                    logger.warning(f"Failed to unmount NFS after verification: {umount_error}")

            return verification_results

        except Exception as e:
            logger.error(f"Post-acquisition verification error: {e}")
            self._log_job(job_id, 'error', f"Verification error: {str(e)}")
            self.lcd.display("Verification", "Error!")
            time.sleep(2)

            # Unmount NFS if we remounted it
            if nfs_remounted:
                try:
                    subprocess.run(['sudo', 'umount', '/mnt/nfs-share'], timeout=10)
                except:
                    pass

            return {'verification_passed': False, 'error': str(e)}

    def _verify_image_integrity(self, job_id, image_path):
        """
        Verify image integrity using ewfverify.
        This reads the image and recalculates hashes to ensure data integrity.
        Returns dict with verification results and hashes.
        """
        logger.info(f"Verifying image integrity: {image_path}")
        self._log_job(job_id, 'info', f"Verifying image integrity using ewfverify...")

        try:
            # Run ewfverify to verify the image
            result = subprocess.run(
                ['ewfverify', '-q', image_path],
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout for verification
            )

            verification_data = {
                'verification_passed': result.returncode == 0,
                'verification_output': result.stdout + result.stderr
            }

            if result.returncode == 0:
                logger.info(f"Image verification PASSED for {image_path}")
                self._log_job(job_id, 'info', "✓ Image verification PASSED - integrity confirmed")
            else:
                logger.error(f"Image verification FAILED for {image_path}")
                self._log_job(job_id, 'error', f"✗ Image verification FAILED - return code {result.returncode}")

            # Extract hashes from verification output or use ewfinfo
            hashes = self._extract_hashes_from_image(image_path, job_id)
            verification_data.update(hashes)

            return verification_data

        except subprocess.TimeoutExpired:
            logger.error(f"Image verification timeout for {image_path}")
            self._log_job(job_id, 'error', "Image verification timeout after 1 hour")
            return {'verification_passed': False, 'error': 'Verification timeout'}
        except FileNotFoundError:
            logger.warning("ewfverify not found - skipping verification")
            self._log_job(job_id, 'warning', "ewfverify not available - skipping post-imaging verification")
            return {'verification_passed': None, 'error': 'ewfverify not installed'}
        except Exception as e:
            logger.error(f"Image verification failed: {e}")
            self._log_job(job_id, 'error', f"Image verification error: {str(e)}")
            return {'verification_passed': False, 'error': str(e)}

    def _extract_hashes_from_image(self, image_path, job_id):
        """Extract hashes from E01 image using ewfinfo."""
        hashes = {}
        try:
            logger.info(f"Extracting hashes from verified image: {image_path}")
            self._log_job(job_id, 'info', "Extracting cryptographic hashes from verified image...")

            result = subprocess.run(
                ['ewfinfo', image_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                output = result.stdout

                # Extract hashes
                md5_match = re.search(r'MD5 hash:\s+([0-9a-f]{32})', output, re.IGNORECASE)
                sha1_match = re.search(r'SHA1 hash:\s+([0-9a-f]{40})', output, re.IGNORECASE)
                sha256_match = re.search(r'SHA256 hash:\s+([0-9a-f]{64})', output, re.IGNORECASE)

                if md5_match:
                    hashes['verified_md5'] = md5_match.group(1)
                    hashes['source_md5'] = md5_match.group(1)
                    hashes['image_md5'] = md5_match.group(1)
                    logger.info(f"Verified MD5: {md5_match.group(1)}")
                if sha1_match:
                    hashes['verified_sha1'] = sha1_match.group(1)
                    hashes['source_sha1'] = sha1_match.group(1)
                    hashes['image_sha1'] = sha1_match.group(1)
                    logger.info(f"Verified SHA1: {sha1_match.group(1)}")
                if sha256_match:
                    hashes['verified_sha256'] = sha256_match.group(1)
                    hashes['source_sha256'] = sha256_match.group(1)
                    hashes['image_sha256'] = sha256_match.group(1)
                    logger.info(f"Verified SHA256: {sha256_match.group(1)}")

                hash_summary = []
                if 'verified_md5' in hashes:
                    hash_summary.append(f"MD5: {hashes['verified_md5']}")
                if 'verified_sha1' in hashes:
                    hash_summary.append(f"SHA1: {hashes['verified_sha1']}")
                if 'verified_sha256' in hashes:
                    hash_summary.append(f"SHA256: {hashes['verified_sha256']}")

                if hash_summary:
                    self._log_job(job_id, 'info', f"Verified hashes: {', '.join(hash_summary)}")
            else:
                logger.warning(f"ewfinfo returned non-zero exit code: {result.returncode}")
                self._log_job(job_id, 'warning', "Could not extract hashes from image metadata")

        except Exception as e:
            logger.warning(f"Failed to extract hashes: {e}")
            self._log_job(job_id, 'warning', f"Hash extraction failed: {str(e)}")

        return hashes

    def _extract_hashes(self, image_path):
        """
        Legacy method - Extract hashes from E01 image using ewfinfo.
        Deprecated: Use _extract_hashes_from_image() instead.
        """
        hashes = {}
        try:
            result = subprocess.run(
                ['ewfinfo', image_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode == 0:
                output = result.stdout

                # Extract hashes
                md5_match = re.search(r'MD5 hash:\s+([0-9a-f]{32})', output, re.IGNORECASE)
                sha1_match = re.search(r'SHA1 hash:\s+([0-9a-f]{40})', output, re.IGNORECASE)
                sha256_match = re.search(r'SHA256 hash:\s+([0-9a-f]{64})', output, re.IGNORECASE)

                if md5_match:
                    hashes['source_md5'] = md5_match.group(1)
                    hashes['image_md5'] = md5_match.group(1)
                if sha1_match:
                    hashes['source_sha1'] = sha1_match.group(1)
                    hashes['image_sha1'] = sha1_match.group(1)
                if sha256_match:
                    hashes['source_sha256'] = sha256_match.group(1)
                    hashes['image_sha256'] = sha256_match.group(1)

                logger.info(f"Extracted hashes: MD5={hashes.get('source_md5', 'N/A')}")
        except Exception as e:
            logger.warning(f"Failed to extract hashes: {e}")

        return hashes

    def _get_smart_data(self, device_path):
        """Collect SMART data from source device using smartctl."""
        try:
            logger.info(f"Collecting SMART data from {device_path}")

            # Run smartctl with JSON output
            result = subprocess.run(
                ['sudo', 'smartctl', '-a', '--json', device_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            # smartctl returns exit code 0 for success, but may return non-zero even if data is valid
            # Exit codes are bit flags: 0=success, 1=command line error, 2=device open failed, etc.
            # We check if we got valid JSON output regardless of exit code
            if result.stdout:
                try:
                    smart_data = json.loads(result.stdout)
                    logger.info(f"SMART data collected successfully from {device_path}")
                    return smart_data
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse smartctl JSON output: {e}")
                    return None
            else:
                logger.warning(f"No output from smartctl for {device_path}")
                return None

        except FileNotFoundError:
            logger.warning("smartctl not found - install smartmontools package")
            return None
        except subprocess.TimeoutExpired:
            logger.warning(f"smartctl timeout for {device_path}")
            return None
        except Exception as e:
            logger.warning(f"Failed to collect SMART data: {e}")
            return None

    def _detect_source_devices(self):
        """Detect connected source storage devices (excluding boot device and config stick)."""
        try:
            # First, find the config stick device to exclude it
            config_stick_device = None
            try:
                result = subprocess.run(
                    ['blkid', '-U', CONFIG_STICK_UUID],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    # Got partition path like /dev/sda1, extract disk name (sda)
                    config_partition = result.stdout.strip()
                    # Remove partition number to get disk name (e.g., /dev/sda1 -> sda)
                    import re
                    match = re.match(r'/dev/([a-z]+)', config_partition)
                    if match:
                        config_stick_device = match.group(1)
                        logger.debug(f"Config stick disk to exclude: {config_stick_device}")
            except Exception as e:
                logger.debug(f"Could not determine config stick device: {e}")

            # List all block devices
            result = subprocess.run(
                ['lsblk', '-d', '-n', '-o', 'NAME,TYPE'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                logger.warning("Failed to list block devices")
                return []

            # Parse output and find disk devices
            devices = []
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    name, dev_type = parts[0], parts[1]
                    # Only include disk types, exclude boot device (mmcblk), loop devices, ram, and config stick
                    if dev_type == 'disk' and not name.startswith(('mmcblk', 'loop', 'ram', 'zram')):
                        # Also exclude config stick device
                        if config_stick_device and name == config_stick_device:
                            logger.debug(f"Excluding config stick device: {name}")
                            continue
                        devices.append(f'/dev/{name}')

            return devices

        except Exception as e:
            logger.warning(f"Failed to detect devices: {e}")
            return []

    def _get_device_size(self, device_path):
        """Get size of a block device in bytes."""
        try:
            result = subprocess.run(
                ['lsblk', '-b', '-d', '-n', '-o', 'SIZE', device_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
            return None
        except Exception as e:
            logger.warning(f"Failed to get device size for {device_path}: {e}")
            return None

    def _find_destination_device(self, source_device):
        """
        Find the destination device (exFAT formatted disk that's not the source).
        Returns (device_path, available_bytes) or (None, None).
        """
        try:
            # Get all block devices with filesystem info
            result = subprocess.run(
                ['lsblk', '-b', '-f', '-n', '-o', 'NAME,FSTYPE,SIZE,MOUNTPOINT'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                return None, None

            # Extract source device name (e.g., 'sda' from '/dev/sda')
            source_name = source_device.replace('/dev/', '')

            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[0].lstrip('└─├─')  # Remove tree characters
                    fstype = parts[1] if len(parts) > 1 else ''
                    size_str = parts[2] if len(parts) > 2 else '0'

                    # Skip if it's the source device or part of source device
                    if name == source_name or name.startswith(source_name):
                        continue

                    # Skip boot device
                    if name.startswith(('mmcblk', 'loop', 'ram', 'zram')):
                        continue

                    # Look for exFAT partition (destination)
                    if fstype.lower() == 'exfat':
                        try:
                            size_bytes = int(size_str)
                            device_path = f'/dev/{name}'
                            logger.info(f"Found exFAT destination: {device_path} ({size_bytes / (1024**3):.1f} GB)")
                            return device_path, size_bytes
                        except ValueError:
                            continue

            return None, None
        except Exception as e:
            logger.warning(f"Failed to find destination device: {e}")
            return None, None

    def _wait_for_source_device(self, job_id, timeout=DISK_WAIT_TIMEOUT):
        """
        Wait for a source device to be connected.
        Uses size-based detection: smaller disk = source (to image), larger disk = destination.
        Returns the device path or None if timeout.
        """
        logger.info(f"Waiting for source device to be connected (timeout: {timeout}s)...")
        self._log_job(job_id, 'info', f"Waiting for source device to be connected (will wait up to {timeout//60} minutes)...")

        start_time = time.time()
        check_count = 0

        while True:
            elapsed = time.time() - start_time

            # Check if timeout reached
            if elapsed >= timeout:
                logger.error(f"Timeout waiting for source device after {timeout}s")
                self._log_job(job_id, 'error', f"No source device detected after {timeout//60} minutes - job failed")
                return None

            # Detect devices
            devices = self._detect_source_devices()

            if devices:
                # Use first detected device
                # Note: If source_device is specified in job config, it's used before this function is called
                device = devices[0]
                logger.info(f"Source device detected: {device}")
                self._log_job(job_id, 'info', f"Source device detected: {device}")

                if len(devices) > 1:
                    logger.info(f"Multiple devices detected: {devices}, using {device}")
                    self._log_job(job_id, 'warning', f"Multiple devices detected ({len(devices)}). Specify source_device in job config for explicit selection.")

                return device

            # Log every 30 seconds to show we're still waiting
            check_count += 1
            if check_count % (30 // DISK_CHECK_INTERVAL) == 0:
                remaining = timeout - elapsed
                logger.info(f"Still waiting for device... ({remaining:.0f}s remaining)")
                self._log_job(job_id, 'info', f"Still waiting for device... ({remaining//60}m {int(remaining%60)}s remaining)")

            # Wait before next check
            time.sleep(DISK_CHECK_INTERVAL)

    def _auto_detect_and_collect_smart(self):
        """Auto-detect connected storage devices and collect SMART data."""
        try:
            devices = self._detect_source_devices()
            logger.info(f"Detected storage devices: {devices}")

            # Try to collect SMART data from each device
            for device in devices:
                smart_data = self._get_smart_data(device)
                if smart_data:
                    # Successfully collected SMART data from this device
                    return smart_data

            logger.warning("No valid SMART data from any detected device")
            return None

        except Exception as e:
            logger.warning(f"Failed to auto-detect devices: {e}")
            return None

    def _complete_job(self, job_id, verification_results=None):
        """Mark job as completed with hash information, SMART data, and verification results."""
        try:
            # Read completion data from imaging script
            completion_data = {}
            completion_file = '/tmp/imaging_completion.json'

            if os.path.exists(completion_file):
                logger.info(f"Reading completion data from {completion_file}")
                try:
                    with open(completion_file, 'r') as f:
                        completion_data = json.load(f)
                    logger.info(f"Successfully loaded completion data: {list(completion_data.keys())}")

                    # Clean up the completion file
                    os.remove(completion_file)
                    logger.info("Cleaned up completion file")
                except Exception as e:
                    logger.warning(f"Failed to read completion file: {e}")
            else:
                logger.warning(f"Completion file not found at {completion_file}")

            # Add pre-imaging SMART data if available
            # This data was collected BEFORE imaging to capture the device state as received
            if hasattr(self, 'pre_imaging_smart_data') and self.pre_imaging_smart_data:
                completion_data['smart_data'] = self.pre_imaging_smart_data
                logger.info("Added pre-imaging SMART data to completion")
                # Clear after use
                self.pre_imaging_smart_data = None
            else:
                logger.warning("No pre-imaging SMART data available")

            # Add post-acquisition verification results
            if verification_results:
                # Merge verification results into completion data
                # Verification hashes override acquisition hashes (more reliable)
                for key in ['source_md5', 'source_sha1', 'source_sha256',
                           'image_md5', 'image_sha1', 'image_sha256',
                           'verified_md5', 'verified_sha1', 'verified_sha256']:
                    if key in verification_results:
                        completion_data[key] = verification_results[key]

                # Add verification status
                completion_data['post_verification_passed'] = verification_results.get('verification_passed')
                logger.info(f"Added verification results to completion (passed: {verification_results.get('verification_passed')})")

            requests.post(
                f"{self.manager_url}/api/jobs/{job_id}/complete/",
                json=completion_data,
                timeout=5
            )
            logger.info(f"Job {job_id} marked as completed")
        except Exception as e:
            logger.error(f"Failed to mark job as completed: {e}")

    def _fail_job(self, job_id, error_message):
        """Mark job as failed."""
        try:
            requests.post(
                f"{self.manager_url}/api/jobs/{job_id}/fail/",
                json={'error_message': error_message},
                timeout=5
            )
            logger.info(f"Job {job_id} marked as failed")
        except Exception as e:
            logger.error(f"Failed to mark job as failed: {e}")

    def _log_job(self, job_id, level, message):
        """Send log entry to manager."""
        try:
            requests.post(
                f"{self.manager_url}/api/jobs/{job_id}/log/",
                json={'level': level, 'message': message},
                timeout=5
            )
        except Exception as e:
            logger.debug(f"Failed to send log: {e}")

    def _check_job_cancelled(self, job_id):
        """Check if job has been cancelled by manager."""
        try:
            response = requests.get(
                f"{self.manager_url}/api/jobs/{job_id}/status/",
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            return data.get('is_cancelled', False)
        except Exception as e:
            logger.debug(f"Failed to check job status: {e}")
            return False

    def _verify_mount_health(self, mount_point='/mnt/destination'):
        """
        Verify that the mount point is still healthy and accessible.
        Returns tuple: (is_healthy, error_message)
        """
        try:
            # Check if mount point exists
            if not os.path.exists(mount_point):
                return False, f"Mount point {mount_point} does not exist"

            # Check if it's actually mounted
            with open('/proc/mounts', 'r') as f:
                mounts = f.read()
                if mount_point not in mounts:
                    return False, f"Mount point {mount_point} is not mounted"

            # Try to access the mount point (read test)
            try:
                os.listdir(mount_point)
            except OSError as e:
                return False, f"Mount point {mount_point} is not accessible: {e}"

            # Try a small write test to verify write capability
            test_file = os.path.join(mount_point, '.acquirepi_mount_test')
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except OSError as e:
                return False, f"Mount point {mount_point} is not writable: {e}"

            return True, None

        except Exception as e:
            return False, f"Mount health check failed: {e}"

    def _remount_destination(self, job_id=None):
        """
        Attempt to remount the destination device using stored UUID.
        Returns True if successful, False otherwise.
        """
        try:
            if not hasattr(self, 'destination_uuid') or not self.destination_uuid:
                logger.error("Cannot remount: destination UUID not stored")
                return False

            uuid = self.destination_uuid
            label = getattr(self, 'destination_label', 'unknown')

            logger.warning(f"Attempting to remount destination UUID={uuid} (label: {label})")
            if job_id:
                self._log_job(job_id, "WARNING", f"Destination mount lost, attempting remount (UUID={uuid})")

            # Try to unmount first (may fail if already unmounted/stale)
            try:
                subprocess.run(['sudo', 'umount', '/mnt/destination'],
                             capture_output=True, timeout=10)
            except Exception:
                pass  # Ignore unmount errors

            # Remount using UUID
            mount_cmd = ['sudo', 'mount', '-t', 'exfat', f'UUID={uuid}', '/mnt/destination']
            result = subprocess.run(mount_cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                error_msg = f"Failed to remount destination UUID={uuid}: {result.stderr}"
                logger.error(error_msg)
                if job_id:
                    self._log_job(job_id, "ERROR", error_msg)
                return False

            logger.info(f"Successfully remounted destination UUID={uuid}")
            if job_id:
                self._log_job(job_id, "INFO", f"Destination remounted successfully (UUID={uuid})")
            return True

        except Exception as e:
            error_msg = f"Remount attempt failed: {e}"
            logger.error(error_msg)
            if job_id:
                self._log_job(job_id, "ERROR", error_msg)
            return False

    # ============================================================================
    # DISK DETECTION (for disk-to-disk imaging)
    # ============================================================================

    def detect_available_disks(self):
        """
        Detect all available disks suitable for imaging.
        Excludes: boot disk, mounted disks, loop devices, swap.
        Returns list of disk dictionaries with detailed information.
        """
        disks = []

        try:
            # Get list of block devices
            result = subprocess.run(
                ['lsblk', '-b', '-d', '-o', 'NAME,SIZE,MODEL,SERIAL,TYPE', '-n'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                logger.warning("Failed to detect disks with lsblk")
                return disks

            # Get blkid info for filesystem details
            blkid_result = subprocess.run(
                ['sudo', 'blkid', '-o', 'export'],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Parse blkid output into dict
            blkid_info = {}
            current_dev = None
            for line in blkid_result.stdout.strip().split('\n'):
                line = line.strip()
                if not line:
                    current_dev = None
                    continue
                if line.startswith('DEVNAME='):
                    current_dev = line.split('=', 1)[1]
                    blkid_info[current_dev] = {}
                elif current_dev and '=' in line:
                    key, value = line.split('=', 1)
                    blkid_info[current_dev][key] = value

            # Get mount info
            mount_result = subprocess.run(
                ['mount'],
                capture_output=True,
                text=True,
                timeout=5
            )
            mounted_devices = set()
            for line in mount_result.stdout.split('\n'):
                if line.startswith('/dev/'):
                    dev = line.split()[0]
                    mounted_devices.add(dev)

            # Parse lsblk output
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue

                parts = line.split()
                if len(parts) < 5:
                    continue

                name = parts[0]
                size = int(parts[1]) if parts[1].isdigit() else 0
                model = ' '.join(parts[2:-2]) if len(parts) > 4 else 'Unknown'
                serial = parts[-2] if len(parts) > 4 else ''
                dev_type = parts[-1]

                device = f'/dev/{name}'

                # Skip if:
                # - Not a disk type
                # - Boot disk (mmcblk0)
                # - Loop device
                # - Less than 1GB (probably not an imaging target)
                if dev_type != 'disk':
                    continue
                if name.startswith('mmcblk'):
                    logger.debug(f"Skipping boot disk: {name}")
                    continue
                if name.startswith('loop'):
                    logger.debug(f"Skipping loop device: {name}")
                    continue
                if name.startswith('zram'):
                    logger.debug(f"Skipping zram device: {name}")
                    continue
                if size < 1_000_000_000:  # 1GB
                    logger.debug(f"Skipping small device: {name} ({size} bytes)")
                    continue

                # Check if any partition is mounted
                is_mounted = False
                for mounted in mounted_devices:
                    if mounted.startswith(device):
                        is_mounted = True
                        logger.debug(f"Device {name} has mounted partition: {mounted}")
                        break

                # Get filesystem info from blkid (check partitions)
                label = None
                fstype = None
                for dev_path, info in blkid_info.items():
                    if dev_path.startswith(device):
                        label = info.get('LABEL', '')
                        fstype = info.get('TYPE', '')
                        break

                # Convert size to human readable
                size_gb = size / (1024**3)
                if size_gb >= 1000:
                    size_human = f"{size_gb/1024:.1f} TB"
                else:
                    size_human = f"{size_gb:.1f} GB"

                disk_info = {
                    'device': device,
                    'name': name,
                    'size': size,
                    'size_human': size_human,
                    'model': model.strip() if model else 'Unknown',
                    'serial': serial.strip() if serial else 'N/A',
                    'label': label or '',
                    'fstype': fstype or '',
                    'mounted': is_mounted
                }

                disks.append(disk_info)
                logger.debug(f"Detected disk: {disk_info}")

            logger.info(f"Detected {len(disks)} available disk(s)")

        except Exception as e:
            logger.error(f"Error detecting disks: {e}")

        return disks

    # ============================================================================
    # MOBILE DEVICE DETECTION (iOS/Android)
    # ============================================================================

    def detect_mobile_devices(self):
        """
        Detect all connected mobile devices (iOS and Android).
        Returns list of device dictionaries with device information.
        """
        devices = []

        # Detect iOS devices
        ios_devices = self._detect_ios_devices()
        devices.extend(ios_devices)

        # Detect Android devices (future implementation)
        # android_devices = self._detect_android_devices()
        # devices.extend(android_devices)

        return devices

    def _detect_ios_devices(self):
        """
        Detect connected iOS devices using libimobiledevice.
        Returns list of device info dictionaries.
        """
        devices = []

        try:
            # List connected iOS device UDIDs
            result = subprocess.run(
                ['idevice_id', '-l'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                logger.debug("No iOS devices detected or idevice_id failed")
                return devices

            udids = [u.strip() for u in result.stdout.strip().split('\n') if u.strip()]

            if not udids:
                return devices

            logger.info(f"Detected {len(udids)} iOS device(s)")

            # Get detailed info for each device
            for udid in udids:
                try:
                    device_info = self._get_ios_device_info(udid)
                    if device_info:
                        devices.append(device_info)
                        logger.info(f"iOS Device: {device_info.get('device_name', 'Unknown')} ({udid[:8]}...)")
                    else:
                        # Device detected but info not available - likely awaiting trust
                        # Try to trigger pairing to prompt trust dialog on device
                        logger.info(f"iOS device {udid[:8]}... detected but not trusted - attempting pair")
                        try:
                            # idevicepair pair will trigger the trust dialog on the device
                            pair_result = subprocess.run(
                                ['idevicepair', '-u', udid, 'pair'],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )
                            if 'SUCCESS' in pair_result.stdout:
                                logger.info(f"Device {udid[:8]}... paired successfully - retrying info")
                                # Retry getting device info after successful pair
                                device_info = self._get_ios_device_info(udid)
                                if device_info:
                                    devices.append(device_info)
                                    logger.info(f"iOS Device (after pair): {device_info.get('device_name', 'Unknown')}")
                            elif 'Please accept' in pair_result.stderr or 'user denied' in pair_result.stderr.lower():
                                logger.info(f"Device {udid[:8]}... waiting for user to tap Trust on device")
                            else:
                                logger.debug(f"Pair attempt for {udid[:8]}...: {pair_result.stdout} {pair_result.stderr}")
                        except Exception as pair_err:
                            logger.debug(f"Could not attempt pairing for {udid[:8]}...: {pair_err}")
                except Exception as e:
                    logger.warning(f"Failed to get info for iOS device {udid}: {e}")

        except FileNotFoundError:
            logger.debug("idevice_id not found - iOS detection unavailable")
        except Exception as e:
            logger.error(f"Error detecting iOS devices: {e}")

        return devices

    def _get_ios_device_info(self, udid):
        """
        Get detailed information about an iOS device.
        Returns dictionary with device information.
        """
        try:
            # Get device info using ideviceinfo
            result = subprocess.run(
                ['ideviceinfo', '-u', udid],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                logger.warning(f"Failed to get iOS device info for {udid}")
                return None

            # Parse ideviceinfo output (key: value format)
            info_dict = {}
            for line in result.stdout.split('\n'):
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    info_dict[key.strip()] = value.strip()

            # Get battery information from battery domain
            try:
                battery_result = subprocess.run(
                    ['ideviceinfo', '-u', udid, '-q', 'com.apple.mobile.battery'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if battery_result.returncode == 0:
                    for line in battery_result.stdout.split('\n'):
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            info_dict[key.strip()] = value.strip()
            except Exception as e:
                logger.debug(f"Could not get battery info: {e}")

            # Get disk usage information
            try:
                disk_result = subprocess.run(
                    ['ideviceinfo', '-u', udid, '-q', 'com.apple.disk_usage'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if disk_result.returncode == 0:
                    for line in disk_result.stdout.split('\n'):
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            info_dict[key.strip()] = value.strip()
            except Exception as e:
                logger.debug(f"Could not get disk usage info: {e}")

            # Get serial number
            serial_number = info_dict.get('SerialNumber', udid)

            # Get storage information using pymobiledevice3 (pass UDID, not serial)
            storage_info = self._get_ios_storage_info(udid)
            if storage_info:
                storage_total = storage_info.get('total_bytes')
                storage_available = storage_info.get('available_bytes')
                storage_used = storage_info.get('used_bytes')
                # If used not available, calculate it
                if storage_total and storage_available and not storage_used:
                    storage_used = storage_total - storage_available
            else:
                storage_total = None
                storage_used = None

            # Extract relevant fields and map to our model
            device_info = {
                'device_type': 'ios',
                'udid': udid,
                'serial_number': serial_number,
                'device_name': info_dict.get('DeviceName', 'iPhone'),
                'model': info_dict.get('ProductType', ''),  # e.g., iPhone13,2
                'manufacturer': 'Apple',
                'product_type': info_dict.get('ProductType', ''),
                'os_version': info_dict.get('ProductVersion', ''),  # e.g., 17.1.1
                'build_version': info_dict.get('BuildVersion', ''),

                # Device class (iPhone, iPad, iPod)
                'ios_device_class': info_dict.get('DeviceClass', ''),
                'ios_hardware_model': info_dict.get('HardwareModel', ''),
                'ios_device_color': info_dict.get('DeviceColor', ''),
                'ios_region_info': info_dict.get('RegionInfo', ''),

                # Storage information (from pymobiledevice3)
                'storage_total_bytes': storage_total,
                'storage_used_bytes': storage_used,

                # Battery information (from com.apple.mobile.battery domain)
                'battery_level': self._parse_ios_battery(info_dict.get('BatteryCurrentCapacity')),
                'battery_state': 'charging' if info_dict.get('BatteryIsCharging', '').lower() == 'true' else 'unplugged',

                # Physical characteristics
                'imei': info_dict.get('InternationalMobileEquipmentIdentity', ''),
                'imei2': info_dict.get('InternationalMobileEquipmentIdentity2', ''),
                'phone_number': info_dict.get('PhoneNumber', ''),
                'iccid': info_dict.get('IntegratedCircuitCardIdentity', ''),
                'wifi_mac': info_dict.get('WiFiAddress', ''),
                'bluetooth_mac': info_dict.get('BluetoothAddress', ''),

                # Device state
                'is_locked': info_dict.get('PasswordProtected', 'true').lower() == 'true',
                'is_encrypted': True,  # iOS devices are always encrypted
                'is_jailbroken': self._check_ios_jailbreak(info_dict),

                # Complete raw info
                'device_info_json': info_dict,
            }

            return device_info

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout getting iOS device info for {udid}")
            return None
        except Exception as e:
            logger.error(f"Error getting iOS device info: {e}")
            return None

    def _get_ios_storage_info(self, udid):
        """Get iOS storage information using pymobiledevice3."""
        try:
            from pymobiledevice3.lockdown import create_using_usbmux

            # Connect to device via USB (pymobiledevice3 uses UDID as "serial")
            lockdown = create_using_usbmux(serial=udid)

            # Get storage information from disk_usage domain
            disk_usage = lockdown.get_value(domain='com.apple.disk_usage')

            if disk_usage:
                # TotalDataCapacity = user-accessible storage area (excludes system partition)
                # TotalDiskCapacity = physical disk size (includes system partition)
                # Use TotalDataCapacity as it's the user-relevant size
                total_capacity = disk_usage.get('TotalDataCapacity')
                available_space = disk_usage.get('AmountDataAvailable')

                if total_capacity is not None and available_space is not None:
                    used_space = total_capacity - available_space
                    return {
                        'total_bytes': total_capacity,
                        'used_bytes': used_space,
                        'available_bytes': available_space,
                    }

            logger.debug(f"Storage info not available for device {udid}")
            return None

        except Exception as e:
            logger.debug(f"Could not get storage info via pymobiledevice3: {e}")
            return None

    def _parse_ios_storage(self, value, invert=False):
        """Parse iOS storage value (in bytes)."""
        if not value:
            return None
        try:
            bytes_val = int(value)
            if invert:
                # For "available" storage, we need total - available
                # This is handled differently - we'll get total separately
                return None
            return bytes_val
        except (ValueError, TypeError):
            return None

    def _parse_ios_battery(self, value):
        """Parse iOS battery percentage."""
        if not value:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def _check_ios_jailbreak(self, info_dict):
        """
        Check if iOS device is jailbroken.
        This is a basic check - more sophisticated methods exist.
        """
        # Check for common jailbreak indicators in device info
        jailbreak_indicators = [
            'Cydia',
            'Sileo',
            'checkra1n',
            'unc0ver',
        ]

        # Check ProductVersion for jailbreak signatures (basic check)
        for indicator in jailbreak_indicators:
            if any(indicator.lower() in str(v).lower() for v in info_dict.values()):
                return True

        return False

    def register_mobile_device(self, device_info):
        """
        Register a mobile device with the manager.
        Returns True if successful, False otherwise.
        """
        try:
            logger.info(f"Registering mobile device: {device_info.get('device_name')} ({device_info.get('serial_number')})")

            response = requests.post(
                f"{self.manager_url}/api/mobile-devices/register/",
                json={
                    'agent_id': self.agent_id,
                    'device_info': device_info
                },
                timeout=10
            )

            response.raise_for_status()
            data = response.json()

            logger.info(f"Mobile device registered successfully: ID {data.get('id')}")
            return data

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to register mobile device: {e}")
            return None
        except Exception as e:
            logger.error(f"Error registering mobile device: {e}")
            return None

    def update_mobile_device_status(self, device_info):
        """
        Update mobile device status (heartbeat).
        Called periodically to update device connection status.
        """
        try:
            response = requests.post(
                f"{self.manager_url}/api/mobile-devices/heartbeat/",
                json={
                    'agent_id': self.agent_id,
                    'serial_number': device_info.get('serial_number'),
                    'udid': device_info.get('udid'),
                    'device_info': device_info
                },
                timeout=5
            )

            response.raise_for_status()
            return True

        except Exception as e:
            logger.debug(f"Failed to update mobile device status: {e}")
            return False

    # ============================================================================
    # MOBILE DEVICE EXTRACTION
    # ============================================================================

    def _execute_mobile_extraction(self, job_info):
        """Execute a mobile device extraction job."""
        # Track what we mounted so we can clean up properly
        nfs_mounted = False
        disk_mounted_by_us = False

        try:
            job_id = job_info['job_id']
            mobile_extraction = job_info.get('mobile_extraction', {})
            device_udid = mobile_extraction.get('udid')
            extraction_method = mobile_extraction.get('extraction_method', 'logical')

            logger.info(f"Starting mobile extraction: method={extraction_method}, udid={device_udid}")
            self._log_job(job_id, "INFO", f"Starting {extraction_method} extraction")

            # Determine backup directory based on upload method
            config = job_info.get('config', {})
            upload_method = config.get('system', {}).get('upload_method', 'disk')
            image_name = config.get('imager-config', {}).get('image_name', 'mobile_backup')

            # Mount NFS if needed
            if upload_method == 'nfs':
                nfs_config = config.get('system', {}).get('nfs-config', {})
                nfs_server = nfs_config.get('server')
                nfs_share = nfs_config.get('share')

                if nfs_server and nfs_share:
                    logger.info(f"Mounting NFS: {nfs_server}:{nfs_share}")
                    self._log_job(job_id, "INFO", f"Mounting NFS: {nfs_server}:{nfs_share}")

                    try:
                        # Unmount if already mounted
                        subprocess.run(['sudo', 'umount', '/mnt/nfs-share'], timeout=10, capture_output=True)
                    except:
                        pass

                    # Create mount point if needed
                    os.makedirs('/mnt/nfs-share', exist_ok=True)

                    # Mount NFS with options for better compatibility
                    mount_cmd = ['sudo', 'mount', '-t', 'nfs', '-o', 'nolock,vers=3,rw', f'{nfs_server}:{nfs_share}', '/mnt/nfs-share']
                    result = subprocess.run(mount_cmd, capture_output=True, text=True, timeout=30)

                    if result.returncode != 0:
                        error_msg = f"Failed to mount NFS: {result.stderr}"
                        logger.error(error_msg)
                        self._log_job(job_id, "ERROR", error_msg)
                        self._fail_job(job_id, error_msg)
                        return False

                    logger.info("NFS mounted successfully")
                    self._log_job(job_id, "INFO", "NFS mounted successfully")
                    nfs_mounted = True  # Track for cleanup

                    # Pre-create backup directory (NFS permissions are server-side)
                    backup_dir = f"/mnt/nfs-share/{image_name}_backup"
                    mkdir_result = subprocess.run(
                        ['sudo', 'mkdir', '-p', backup_dir],
                        capture_output=True, text=True, timeout=60
                    )
                    if mkdir_result.returncode != 0:
                        # Try without sudo if root_squash is active
                        logger.warning(f"mkdir with sudo failed: {mkdir_result.stderr}, trying without sudo")
                        try:
                            os.makedirs(backup_dir, exist_ok=True)
                        except PermissionError as e:
                            error_msg = f"Cannot create backup directory on NFS: {e}. Check NFS export permissions."
                            logger.error(error_msg)
                            self._log_job(job_id, "ERROR", error_msg)
                            self._fail_job(job_id, error_msg)
                            return False
                    logger.info(f"Backup directory created: {backup_dir}")
                else:
                    error_msg = "NFS upload method selected but no NFS server/share configured"
                    logger.error(error_msg)
                    self._log_job(job_id, "ERROR", error_msg)
                    self._fail_job(job_id, error_msg)
                    return False
            else:  # disk
                # Check for and clean up stacked mounts before mounting
                try:
                    # Get all mounts at /mnt/destination
                    mount_check = subprocess.run(
                        ['mount'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    destination_mounts = [line for line in mount_check.stdout.split('\n')
                                        if '/mnt/destination' in line and line.strip()]

                    if len(destination_mounts) > 1:
                        logger.warning(f"Detected {len(destination_mounts)} stacked mounts at /mnt/destination - cleaning up")
                        self._log_job(job_id, "WARNING", f"Cleaning up {len(destination_mounts)} stacked mounts")

                        # Unmount all stacked mounts
                        for _ in range(len(destination_mounts)):
                            subprocess.run(['sudo', 'umount', '/mnt/destination'],
                                         capture_output=True, timeout=10)

                        logger.info("Stacked mounts cleaned up")
                        self._log_job(job_id, "INFO", "Stacked mounts cleaned up")

                    elif len(destination_mounts) == 1:
                        # Single mount exists - verify it's working
                        logger.info("Verifying existing mount at /mnt/destination")
                        mount_is_healthy = False
                        try:
                            # Test if mount is accessible (not corrupted)
                            test_result = subprocess.run(
                                ['ls', '/mnt/destination'],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )

                            if test_result.returncode == 0:
                                logger.info("/mnt/destination already mounted and accessible")
                                self._log_job(job_id, "INFO", "Destination already mounted and verified")
                                mount_is_healthy = True
                            else:
                                # Mount is corrupted, unmount and remount
                                logger.warning("Existing mount corrupted (ls failed) - remounting")
                                self._log_job(job_id, "WARNING", "Existing mount corrupted - remounting")
                                subprocess.run(['sudo', 'umount', '/mnt/destination'],
                                             capture_output=True, timeout=10)
                        except subprocess.TimeoutExpired:
                            # ls command hung - mount is definitely corrupted
                            logger.warning("Existing mount corrupted (ls timeout) - force unmounting")
                            self._log_job(job_id, "WARNING", "Existing mount corrupted - force unmounting")
                            subprocess.run(['sudo', 'umount', '-f', '/mnt/destination'],
                                         capture_output=True, timeout=10)
                        except Exception as e:
                            # I/O error or other issue - force unmount
                            logger.warning(f"Mount verification failed ({e}) - force unmounting")
                            self._log_job(job_id, "WARNING", f"Mount check failed - force unmounting: {e}")
                            subprocess.run(['sudo', 'umount', '-f', '/mnt/destination'],
                                         capture_output=True, timeout=10)

                except Exception as e:
                    logger.warning(f"Error checking mounts: {e} - proceeding with mount attempt")

                # Get UUID of destination device (needed for remounting if mount fails during backup)
                # This must be done even if mount already exists
                try:
                    # Check if destination device is specified in config (from manager)
                    specified_dest = config.get('system', {}).get('source_device')  # For mobile, source_device = destination

                    result = subprocess.run(
                        ['sudo', 'blkid', '-o', 'export'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )

                    destination_uuid = None
                    destination_device = None
                    destination_label = None
                    destination_size = 0
                    current_devname = None
                    current_type = None
                    current_uuid = None
                    current_label = None

                    # Collect all exFAT devices
                    exfat_devices = []
                    specified_device_info = None  # Track if we find the specified device

                    # Parse blkid output
                    for line in result.stdout.strip().split('\n'):
                        line = line.strip()
                        if not line:
                            if current_type == 'exfat' and current_uuid and current_devname:
                                # Get device size
                                size = self._get_device_size(current_devname.rstrip('0123456789')) or 0
                                exfat_devices.append({
                                    'device': current_devname,
                                    'uuid': current_uuid,
                                    'label': current_label or 'unlabeled',
                                    'size': size
                                })
                                logger.info(f"Found exFAT device: {current_devname} UUID={current_uuid} LABEL={current_label} SIZE={size/(1024**3):.1f}GB")
                            current_devname = None
                            current_type = None
                            current_uuid = None
                            current_label = None
                            continue

                        if line.startswith('DEVNAME='):
                            current_devname = line.split('=', 1)[1]
                        elif line.startswith('TYPE='):
                            current_type = line.split('=', 1)[1]
                        elif line.startswith('UUID='):
                            current_uuid = line.split('=', 1)[1]
                        elif line.startswith('LABEL='):
                            current_label = line.split('=', 1)[1]

                    # Check last device in output (might not have trailing empty line)
                    if current_type == 'exfat' and current_uuid and current_devname:
                        size = self._get_device_size(current_devname.rstrip('0123456789')) or 0
                        exfat_devices.append({
                            'device': current_devname,
                            'uuid': current_uuid,
                            'label': current_label or 'unlabeled',
                            'size': size
                        })
                        logger.info(f"Found exFAT device (last): {current_devname} UUID={current_uuid} LABEL={current_label} SIZE={size/(1024**3):.1f}GB")

                    # Select destination device
                    if exfat_devices:
                        # First, check if a specific device was specified in the config
                        if specified_dest:
                            # Look for the specified device (match by path like /dev/sda1)
                            for dev in exfat_devices:
                                # Match by device path (e.g., /dev/sda1 or /dev/sda)
                                if dev['device'] == specified_dest or dev['device'].startswith(specified_dest):
                                    destination_uuid = dev['uuid']
                                    destination_device = dev['device']
                                    destination_label = dev['label']
                                    logger.info(f"Using specified destination device from config: {destination_device} ({dev['size']/(1024**3):.1f}GB)")
                                    break
                            if not destination_uuid:
                                logger.warning(f"Specified destination {specified_dest} not found or not exFAT, falling back to largest")

                        # Fallback: use largest exFAT device
                        if not destination_uuid:
                            exfat_devices.sort(key=lambda x: x['size'], reverse=True)
                            best = exfat_devices[0]
                            destination_uuid = best['uuid']
                            destination_device = best['device']
                            destination_label = best['label']
                            logger.info(f"Selected largest exFAT device as destination: {destination_device} ({best['size']/(1024**3):.1f}GB)")

                    if destination_uuid:
                        # Store UUID for mount health monitoring
                        self.destination_uuid = destination_uuid
                        self.destination_label = destination_label
                        logger.info(f"Stored destination UUID={destination_uuid} for monitoring")
                    else:
                        logger.warning("No exFAT destination device found - will fail if mount needed")

                except Exception as e:
                    logger.warning(f"Failed to get destination UUID: {e}")

                # Mount destination if not already mounted (or after cleanup)
                if not os.path.ismount('/mnt/destination'):
                    if not destination_uuid:
                        error_msg = "No exFAT formatted destination device found for mobile backup"
                        logger.error(error_msg)
                        self._log_job(job_id, "ERROR", error_msg)
                        self._fail_job(job_id, error_msg)
                        return False

                    logger.info("Mounting destination device for mobile backup")
                    self._log_job(job_id, "INFO", "Mounting destination device")

                    try:
                        # Create mount point
                        os.makedirs('/mnt/destination', exist_ok=True)
                        logger.info("Mount point /mnt/destination created/verified")

                        # Mount the device using UUID (survives device name changes)
                        mount_cmd = ['sudo', 'mount', '-t', 'exfat', f'UUID={destination_uuid}', '/mnt/destination']
                        result = subprocess.run(mount_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode != 0:
                            error_msg = f"Failed to mount destination UUID={destination_uuid}: {result.stderr}"
                            logger.error(error_msg)
                            self._log_job(job_id, "ERROR", error_msg)
                            self._fail_job(job_id, error_msg)
                            return False

                        logger.info(f"Mounted UUID={destination_uuid} (label '{destination_label}') to /mnt/destination")
                        self._log_job(job_id, "INFO", f"Destination device mounted successfully (UUID={destination_uuid})")
                        disk_mounted_by_us = True  # Track for cleanup
                    except Exception as e:
                        error_msg = f"Failed to mount destination: {str(e)}"
                        logger.error(error_msg)
                        self._log_job(job_id, "ERROR", error_msg)
                        self._fail_job(job_id, error_msg)
                        return False

                backup_dir = f"/mnt/destination/{image_name}_backup"

            logger.info(f"Backup directory: {backup_dir}")
            self._log_job(job_id, "INFO", f"Backup location: {backup_dir}")

            # Check destination disk capacity before starting backup
            try:
                # Get destination mount point
                if backup_dir.startswith('/mnt/destination'):
                    mount_point = '/mnt/destination'
                elif backup_dir.startswith('/mnt/nfs-share'):
                    mount_point = '/mnt/nfs-share'
                else:
                    mount_point = None

                if mount_point:
                    disk_usage = psutil.disk_usage(mount_point)
                    available_gb = disk_usage.free / (1024 ** 3)

                    # Get estimated backup size from mobile device storage
                    device_storage_used = mobile_extraction.get('device_storage_used_bytes', 0)

                    # If we don't have device storage info, try to get it from the device
                    if not device_storage_used and device_udid:
                        try:
                            device_info = self._get_ios_device_info(device_udid)
                            if device_info:
                                device_storage_used = device_info.get('storage_used_bytes', 0)
                        except Exception as e:
                            logger.debug(f"Could not get device storage info: {e}")

                    if device_storage_used:
                        required_gb = device_storage_used / (1024 ** 3)
                        # Add 10% buffer for safety
                        required_with_buffer = required_gb * 1.1

                        logger.info(f"Destination space: {available_gb:.1f} GB available, estimated backup: {required_gb:.1f} GB")
                        self._log_job(job_id, "INFO", f"Disk space check: {available_gb:.1f} GB available, need ~{required_gb:.1f} GB")

                        if available_gb < required_with_buffer:
                            error_msg = f"Not enough disk space. Available: {available_gb:.1f} GB, Required: ~{required_gb:.1f} GB (device used storage + 10% buffer)"
                            logger.error(error_msg)
                            self._log_job(job_id, "ERROR", error_msg)
                            self._fail_job(job_id, error_msg)
                            return False

                        self._log_job(job_id, "INFO", "Disk space check passed")
                    else:
                        # No device storage info - just warn about available space
                        logger.info(f"Destination has {available_gb:.1f} GB available (device storage unknown)")
                        self._log_job(job_id, "INFO", f"Destination has {available_gb:.1f} GB available")

                        # Fail if less than 10GB available as a safety minimum
                        if available_gb < 10:
                            error_msg = f"Destination has only {available_gb:.1f} GB available. Minimum 10 GB recommended for mobile backups."
                            logger.error(error_msg)
                            self._log_job(job_id, "ERROR", error_msg)
                            self._fail_job(job_id, error_msg)
                            return False
            except Exception as e:
                logger.warning(f"Could not check destination disk space: {e}")
                self._log_job(job_id, "WARNING", f"Could not verify disk space: {e}")

            # Perform extraction based on method and device type
            # Only consensual, legitimate extraction methods supported
            success = False
            if extraction_method == 'logical':
                # iOS/Android logical backup using standard protocols
                # iOS: idevicebackup2 (requires device unlocked and trusted)
                # Android: adb backup (requires USB debugging enabled and authorized)
                success = self.perform_ios_backup(job_info, device_udid, backup_dir)
            else:
                self._log_job(job_id, "ERROR", f"Unsupported extraction method: {extraction_method}")
                logger.error(f"Invalid extraction method requested: {extraction_method}")
                return False

            if success:
                # Calculate final backup size
                backup_size = self._calculate_directory_size(backup_dir)

                # Count files extracted
                file_count = 0
                try:
                    for dirpath, dirnames, filenames in os.walk(backup_dir):
                        file_count += len(filenames)
                except Exception as e:
                    logger.warning(f"Failed to count extracted files: {e}")

                # Write completion data to file for _complete_job to read
                completion_data = {
                    'output_path': backup_dir,
                    'image_size': backup_size,
                    'extraction_method': extraction_method,
                    'files_extracted': file_count
                }

                try:
                    import json
                    with open('/tmp/imaging_completion.json', 'w') as f:
                        json.dump(completion_data, f)
                    logger.info(f"Wrote mobile extraction completion data: {backup_size} bytes, {file_count} files")
                except Exception as e:
                    logger.warning(f"Failed to write completion data: {e}")

                self._complete_job(job_id, None)
                self.lcd.display("Extraction", "Complete!")
                time.sleep(2)
            else:
                self._fail_job(job_id, "Mobile extraction failed")
                self.lcd.display("Extraction", "Failed!")
                time.sleep(3)

        except Exception as e:
            logger.error(f"Mobile extraction error: {e}")
            self._log_job(job_id, "ERROR", f"Mobile extraction error: {str(e)}")
            self._fail_job(job_id, str(e))
            self.lcd.display("Error!", str(e)[:16])
            time.sleep(3)
        finally:
            # Cleanup: Unmount what we mounted
            logger.info("Cleaning up mobile extraction mounts")

            # Unmount NFS if we mounted it
            if nfs_mounted:
                try:
                    logger.info("Unmounting NFS share")
                    result = subprocess.run(['sudo', 'umount', '/mnt/nfs-share'],
                                          timeout=10, capture_output=True, text=True)
                    if result.returncode == 0:
                        logger.info("NFS unmounted successfully")
                    else:
                        logger.warning(f"NFS unmount returned {result.returncode}: {result.stderr}")
                except Exception as e:
                    logger.warning(f"Failed to unmount NFS: {e}")

            # Unmount disk destination if we mounted it
            if disk_mounted_by_us:
                try:
                    logger.info("Unmounting destination disk")
                    result = subprocess.run(['sudo', 'umount', '/mnt/destination'],
                                          timeout=10, capture_output=True, text=True)
                    if result.returncode == 0:
                        logger.info("Destination disk unmounted successfully")
                    else:
                        # Try force unmount if normal unmount fails
                        logger.warning(f"Normal unmount failed, attempting force unmount")
                        force_result = subprocess.run(['sudo', 'umount', '-f', '/mnt/destination'],
                                                    timeout=10, capture_output=True, text=True)
                        if force_result.returncode == 0:
                            logger.info("Destination disk force unmounted")
                        else:
                            logger.error(f"Force unmount also failed: {force_result.stderr}")
                except Exception as e:
                    logger.warning(f"Failed to unmount destination: {e}")

            # Clear stored UUIDs
            if hasattr(self, 'destination_uuid'):
                delattr(self, 'destination_uuid')
            if hasattr(self, 'destination_label'):
                delattr(self, 'destination_label')

            self.current_job = None
            logger.info("Mobile extraction cleanup complete")

    # ============================================================================
    # iOS BACKUP EXTRACTION
    # ============================================================================

    def perform_ios_backup(self, job_info, udid, backup_dir):
        """
        Perform iOS logical backup using pymobiledevice3.

        This is a CONSENSUAL, LEGITIMATE extraction method that uses the standard
        iTunes backup protocol. No jailbreak or exploits required.

        REQUIREMENTS:
        - Device must be unlocked (passcode entered by owner)
        - Device must trust this computer (user must tap "Trust" on device)
        - Uses standard Apple backup API (same as iTunes/Finder backups)

        LIMITATIONS:
        - Only extracts data that apps include in backups
        - Does NOT extract: system files, deleted data, app binaries
        - Some apps exclude sensitive data from backups

        Args:
            job_info: Job information dictionary
            udid: iOS device UDID
            backup_dir: Directory to store backup

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info(f"Starting iOS logical backup for device {udid}")
            self._log_job(job_info['job_id'], "INFO", f"Starting iOS logical backup to {backup_dir}")

            # Create backup directory
            os.makedirs(backup_dir, exist_ok=True)

            # Check if backup should be encrypted
            mobile_extraction = job_info.get('mobile_extraction')
            if mobile_extraction and mobile_extraction.get('backup_encrypted'):
                backup_password = mobile_extraction.get('backup_password', '')
                if backup_password:
                    logger.info("Enabling backup encryption on device")
                    self._log_job(job_info['job_id'], "INFO", "Enabling backup encryption on device")

                    # Enable backup encryption on the device
                    encryption_cmd = ['python3', '-m', 'pymobiledevice3', 'backup2', 'encryption', 'on', backup_password, '--udid', udid]
                    logger.info(f"Executing: python3 -m pymobiledevice3 backup2 encryption on [PASSWORD] --udid {udid}")

                    try:
                        result = subprocess.run(
                            encryption_cmd,
                            capture_output=True,
                            text=True,
                            timeout=60
                        )

                        if result.returncode == 0:
                            logger.info("Backup encryption enabled successfully")
                            self._log_job(job_info['job_id'], "INFO", "Backup encryption enabled on device")
                        else:
                            logger.error(f"Failed to enable encryption: {result.stderr}")
                            self._log_job(job_info['job_id'], "ERROR", f"Failed to enable encryption: {result.stderr}")
                            return False
                    except subprocess.TimeoutExpired:
                        logger.error("Encryption setup timed out")
                        self._log_job(job_info['job_id'], "ERROR", "Encryption setup timed out")
                        return False
                    except Exception as e:
                        logger.error(f"Error enabling encryption: {e}")
                        self._log_job(job_info['job_id'], "ERROR", f"Error enabling encryption: {str(e)}")
                        return False
                else:
                    logger.warning("Encrypted backup requested but no password provided")
                    self._log_job(job_info['job_id'], "WARNING", "Encrypted backup requested but no password provided")

            # Build pymobiledevice3 backup command
            cmd = ['python3', '-m', 'pymobiledevice3', '-v', 'backup2', 'backup', '--udid', udid, '--full', backup_dir]

            logger.info(f"Executing: {' '.join(cmd)}")
            self._log_job(job_info['job_id'], "INFO", f"Executing iOS backup command (pymobiledevice3)")

            # Start LED blinking to indicate backup in progress
            self._led_start_blink(interval=0.1)

            # Execute backup with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Monitor backup progress
            import time
            import re
            import select
            last_progress_report = 0
            last_device_check = time.time()
            last_mount_check = time.time()
            last_keepalive = time.time()
            last_known_progress = 0.0
            KEEPALIVE_INTERVAL = 30  # Send keepalive every 30 seconds even without output

            while True:
                # Use select with timeout to avoid blocking indefinitely on readline
                # This allows us to send keepalives even when pymobiledevice3 is silent
                ready, _, _ = select.select([process.stdout], [], [], KEEPALIVE_INTERVAL)

                if ready:
                    line = process.stdout.readline()
                    if not line:
                        break  # EOF - process finished
                else:
                    # Timeout - no output from pymobiledevice3, send keepalive
                    current_time = time.time()
                    if current_time - last_keepalive >= KEEPALIVE_INTERVAL:
                        logger.debug(f"Sending keepalive (no output for {KEEPALIVE_INTERVAL}s)")
                        # Send progress update with last known progress to keep agent alive
                        try:
                            if self._update_progress(job_info['job_id'], round(last_known_progress, 2)):
                                logger.info("Job cancelled (detected via keepalive), terminating iOS backup")
                                process.terminate()
                                try:
                                    process.wait(timeout=10)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                self._led_stop_blink()
                                return False
                        except Exception as e:
                            logger.debug(f"Keepalive progress update failed: {e}")
                        last_keepalive = current_time
                    continue  # Go back to waiting for output

                line = line.strip()
                if line:
                    logger.info(f"pymobiledevice3: {line}")

                    # Report interesting lines to manager
                    if any(keyword in line.lower() for keyword in ['backup', 'file', 'completed', 'finished', 'error', 'failed', 'copying', 'progress']):
                        self._log_job(job_info['job_id'], "INFO", line)

                    # Parse actual progress from pymobiledevice3 output
                    # Format: "99%|█████████▉| 98.78084514502050/100 [59:40<00:44, 36.24s/it]"
                    progress_match = re.search(r'\|\s*([\d.]+)/100\s*\[', line)
                    if progress_match:
                        try:
                            progress = float(progress_match.group(1))
                            last_known_progress = progress  # Store for keepalive updates
                            current_time = time.time()
                            # Report progress every 5 seconds to avoid too many API calls
                            if current_time - last_progress_report > 5:
                                # Round to 2 decimal places to match serializer requirements
                                # Also check if job was cancelled via progress response
                                if self._update_progress(job_info['job_id'], round(progress, 2)):
                                    logger.info("Job cancelled (detected via progress update), terminating iOS backup")
                                    process.terminate()
                                    try:
                                        process.wait(timeout=10)
                                    except subprocess.TimeoutExpired:
                                        process.kill()
                                    self._led_stop_blink()
                                    return False
                                last_progress_report = current_time
                                last_keepalive = current_time  # Reset keepalive timer
                        except (ValueError, IndexError):
                            pass

                # Periodically check if device is still connected (every 30 seconds)
                current_time = time.time()
                if current_time - last_device_check > 30:
                    try:
                        # Check if device is still available
                        check_cmd = ['python3', '-m', 'pymobiledevice3', 'usbmux', 'list']
                        check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=5)

                        if udid not in check_result.stdout:
                            logger.error(f"Device {udid} no longer detected - aborting backup")
                            self._log_job(job_info['job_id'], "ERROR", f"Device disconnected during backup")
                            process.terminate()
                            try:
                                process.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                process.kill()
                            self._led_stop_blink()
                            return False

                        last_device_check = current_time

                        # Send heartbeat during device check to keep agent status updated
                        # This is important because pymobiledevice3 progress updates are infrequent
                        try:
                            self.heartbeat()
                        except Exception as hb_err:
                            logger.debug(f"Heartbeat during backup: {hb_err}")
                    except Exception as e:
                        logger.warning(f"Failed to check device availability: {e}")
                        # Don't abort on check failure, just log it

                # Periodically check mount health (every 30 seconds)
                # Determine which mount point to check based on backup directory
                if current_time - last_mount_check > 30:
                    try:
                        # Determine mount point from backup_dir
                        if backup_dir.startswith('/mnt/destination'):
                            mount_point = '/mnt/destination'
                        elif backup_dir.startswith('/mnt/nfs-share'):
                            mount_point = '/mnt/nfs-share'
                        elif backup_dir.startswith('/tmp'):
                            # S3 mode - no mount to check
                            mount_point = None
                        else:
                            # Unknown location - try to detect
                            mount_point = None
                            logger.warning(f"Unknown backup location {backup_dir}, skipping mount health check")

                        if mount_point:
                            is_healthy, error_msg = self._verify_mount_health(mount_point)

                            if not is_healthy:
                                logger.warning(f"Mount {mount_point} unhealthy: {error_msg}")
                                self._log_job(job_info['job_id'], "WARNING", f"Mount health issue: {error_msg}")

                                # Only attempt remount for disk mode (/mnt/destination)
                                if mount_point == '/mnt/destination':
                                    # Attempt to remount
                                    if self._remount_destination(job_info['job_id']):
                                        logger.info("Successfully remounted destination - continuing backup")
                                        self._log_job(job_info['job_id'], "INFO", "Destination remounted, backup continuing")
                                    else:
                                        # Remount failed - abort backup
                                        logger.error("Failed to remount destination - aborting backup")
                                        self._log_job(job_info['job_id'], "ERROR", "Destination mount failed, backup aborted")
                                        process.terminate()
                                        try:
                                            process.wait(timeout=10)
                                        except subprocess.TimeoutExpired:
                                            process.kill()
                                        self._led_stop_blink()
                                        return False
                                else:
                                    # NFS mount failed - can't remount easily, abort
                                    logger.error(f"Mount {mount_point} failed - aborting backup")
                                    self._log_job(job_info['job_id'], "ERROR", f"Mount {mount_point} failed, backup aborted")
                                    process.terminate()
                                    try:
                                        process.wait(timeout=10)
                                    except subprocess.TimeoutExpired:
                                        process.kill()
                                    self._led_stop_blink()
                                    return False

                        last_mount_check = current_time
                    except Exception as e:
                        logger.warning(f"Failed to check mount health: {e}")
                        # Don't abort on check failure, just log it

                # Check if job was cancelled
                if self._check_job_cancelled(job_info['job_id']):
                    logger.info("Job cancelled, terminating iOS backup")
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                    self._led_stop_blink()
                    return False

            # Wait for process to complete
            return_code = process.wait()

            if return_code == 0:
                # CRITICAL: Validate backup actually succeeded before reporting success
                # pymobiledevice3 sometimes exits 0 even when device disconnects

                # Calculate backup size
                backup_size = self._calculate_directory_size(backup_dir)

                # Count files in backup
                file_count = 0
                try:
                    for dirpath, dirnames, filenames in os.walk(backup_dir):
                        file_count += len(filenames)
                except Exception as e:
                    logger.error(f"Failed to count backup files: {e}")

                logger.info(f"Backup validation: {file_count} files, {backup_size / (1024**3):.2f} GB")

                # Validate backup has actual content
                if file_count == 0:
                    logger.error("Backup reported success but contains 0 files - backup failed")
                    self._log_job(job_info['job_id'], "ERROR", "Backup validation failed: 0 files extracted")
                    return False

                if backup_size < 1024:  # Less than 1KB is suspicious
                    logger.error(f"Backup reported success but only {backup_size} bytes - likely incomplete")
                    self._log_job(job_info['job_id'], "ERROR", f"Backup validation failed: only {backup_size} bytes")
                    return False

                # Check for iOS backup structure (Info.plist or Snapshot directory)
                # Note: pymobiledevice3 creates different structures than iTunes
                manifest_db = os.path.join(backup_dir, 'Manifest.db')
                info_plist = os.path.join(backup_dir, 'Info.plist')
                snapshot_dir = os.path.join(backup_dir, 'Snapshot')

                has_backup_structure = False
                backup_type = "unknown"

                # Check for traditional iTunes/libimobiledevice backup structure
                if os.path.exists(info_plist):
                    has_backup_structure = True
                    backup_type = "iTunes-style backup"
                    logger.info("Detected iTunes-style backup structure (Info.plist found)")
                    self._log_job(job_info['job_id'], "INFO", "Backup type: iTunes-style")

                # Check for pymobiledevice3 backup structure (may have Snapshot dir or just files)
                elif os.path.exists(snapshot_dir) or file_count > 1000:
                    has_backup_structure = True
                    backup_type = "pymobiledevice3 backup"
                    logger.info("Detected pymobiledevice3 backup structure")
                    self._log_job(job_info['job_id'], "INFO", "Backup type: pymobiledevice3")

                # Warn if no recognizable structure but has files (still count as success)
                if not has_backup_structure and file_count > 0:
                    logger.warning(f"Backup structure not recognized, but {file_count} files extracted - accepting as valid")
                    self._log_job(job_info['job_id'], "WARNING", f"Non-standard backup structure, but {file_count} files extracted")
                    backup_type = "non-standard backup"

                # Log backup structure details
                if os.path.exists(manifest_db):
                    logger.info("Found Manifest.db (file mapping database)")
                    self._log_job(job_info['job_id'], "INFO", "Manifest.db present")
                else:
                    logger.info("No Manifest.db (normal for pymobiledevice3)")

                # Validation passed - we have files and reasonable size
                logger.info(f"iOS backup completed and validated successfully ({backup_type})")
                self._log_job(job_info['job_id'], "INFO", f"iOS backup completed successfully ({backup_type})")
                logger.info(f"Backup size: {backup_size / (1024**3):.2f} GB, Files: {file_count:,}")
                self._log_job(job_info['job_id'], "INFO", f"Backup size: {backup_size / (1024**3):.2f} GB, Files: {file_count:,}")

                # Parse backup contents
                self._parse_ios_backup(job_info['job_id'], backup_dir)

                self._led_stop_blink()
                return True
            else:
                logger.error(f"iOS backup failed with return code {return_code}")
                self._log_job(job_info['job_id'], "ERROR", f"iOS backup failed with return code {return_code}")
                self._led_stop_blink()
                return False

        except subprocess.TimeoutExpired:
            logger.error("iOS backup timed out")
            self._log_job(job_info['job_id'], "ERROR", "iOS backup timed out")
            self._led_stop_blink()
            return False
        except Exception as e:
            logger.error(f"Error performing iOS backup: {e}")
            self._log_job(job_info['job_id'], "ERROR", f"iOS backup error: {str(e)}")
            self._led_stop_blink()
            return False

    def _calculate_directory_size(self, directory):
        """Calculate total size of directory in bytes."""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
        except Exception as e:
            logger.warning(f"Error calculating directory size: {e}")
        return total_size

    def _parse_ios_backup(self, job_id, backup_dir):
        """
        Parse iOS backup to extract metadata and statistics.
        This provides forensic documentation of what was extracted.
        """
        try:
            self._log_job(job_id, "INFO", "Parsing iOS backup contents...")

            # Count files
            file_count = 0
            for dirpath, dirnames, filenames in os.walk(backup_dir):
                file_count += len(filenames)

            self._log_job(job_id, "INFO", f"Backup contains {file_count} files")

            # Look for Info.plist (backup metadata)
            info_plist = os.path.join(backup_dir, 'Info.plist')
            if os.path.exists(info_plist):
                self._log_job(job_id, "INFO", "Found backup metadata (Info.plist)")
                # Could parse plist here for more details

            # Look for Manifest files
            manifest_plist = os.path.join(backup_dir, 'Manifest.plist')
            manifest_db = os.path.join(backup_dir, 'Manifest.db')

            if os.path.exists(manifest_db):
                self._log_job(job_id, "INFO", "Found Manifest.db (file mapping database)")
                # Could query SQLite database for file listings

            if os.path.exists(manifest_plist):
                self._log_job(job_id, "INFO", "Found Manifest.plist (backup properties)")

            # Look for common forensic artifacts (basic check)
            status_plist = os.path.join(backup_dir, 'Status.plist')
            if os.path.exists(status_plist):
                self._log_job(job_id, "INFO", "Backup completed successfully (Status.plist present)")

            logger.info(f"iOS backup parsing complete: {file_count} files")

        except Exception as e:
            logger.warning(f"Error parsing iOS backup: {e}")
            self._log_job(job_id, "WARNING", f"Could not fully parse backup: {str(e)}")

    def run_standalone_mode(self):
        """Run in standalone mode using USB config stick."""
        logger.info("Starting standalone mode")

        # Turn off ACT LED at boot in airgapped mode (indicates ready state)
        self._led_control(1)  # 1 = OFF (active-low on Pi 5)
        logger.debug("ACT LED turned off for standalone mode")

        self.lcd.display("Standalone Mode", "Ready")

        try:
            # Read config from USB stick
            with open(CONFIG_PATH, 'r') as f:
                config = yaml.safe_load(f)

            logger.info(f"Loaded config from {CONFIG_PATH}")

            # Create a pseudo job ID for standalone mode
            job_id = 1
            self.current_job = job_id

            # Check extraction type - disk (default) or mobile
            extraction_type = config.get('system', {}).get('extraction_type', 'disk')
            case_num = config.get('imager-config', {}).get('case_number', 'N/A')

            if extraction_type == 'mobile':
                # Mobile device extraction mode
                self._run_standalone_mobile_extraction(job_id, config, case_num)
            else:
                # Disk imaging mode (default)
                self._run_standalone_disk_imaging(job_id, config, case_num)

        except Exception as e:
            logger.error(f"Standalone mode error: {e}")
            self.lcd.display("Error", str(e)[:16])
            time.sleep(10)

        # Wait for config stick to be removed before exiting (prevents restart loop)
        logger.info("Waiting for config stick to be removed...")
        self.lcd.display("Remove config", "stick to exit")
        while self.check_usb_config_stick():
            time.sleep(5)

        logger.info("Config stick removed, exiting standalone mode")
        self.lcd.display("Config Removed", "Shutting down")
        logger.info("Standalone mode finished - exiting")

    def _run_standalone_disk_imaging(self, job_id, config, case_num):
        """Run disk imaging in standalone mode."""
        logger.info("Starting standalone disk imaging job")
        self.lcd.display("Disk Imaging", f"Case: {case_num}")

        # Wait for source device to be connected
        logger.info("Checking for source device...")
        self.lcd.display("Waiting for", "source device...")
        source_device = self._wait_for_source_device(job_id)

        if not source_device:
            error = "Source device not detected within timeout period"
            logger.error(error)
            self.lcd.display("Device timeout!", "Check connection")
            time.sleep(5)
            return

        # Get upload method and run appropriate script
        upload_method = config.get('system', {}).get('upload_method', 'disk')
        logger.info(f"Starting {upload_method} imaging")
        self.lcd.display("Imaging", f"{upload_method} mode")

        script_map = {
            'disk': '/usr/local/bin/disk_mount.sh',
            'nfs': '/usr/local/bin/nfs-imager.sh',
        }

        script = script_map.get(upload_method)
        if not script:
            error = f"Unknown upload method: {upload_method}"
            logger.error(error)
            self.lcd.display("Error", error[:16])
            return

        # Run the imaging script directly
        logger.info(f"Executing: {script}")
        process = subprocess.Popen(
            [script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            bufsize=1
        )

        # Monitor output
        for line in process.stdout:
            logger.info(line.strip())

        process.wait()

        if process.returncode == 0:
            logger.info("Standalone disk imaging completed successfully")
            self.lcd.display("Job Complete", "Remove config")
        else:
            logger.error(f"Standalone disk imaging failed with exit code {process.returncode}")
            self.lcd.display("Job Failed", "Remove config")

    def _run_standalone_mobile_extraction(self, job_id, config, case_num):
        """Run mobile device extraction in standalone mode."""
        logger.info("Starting standalone mobile extraction job")
        self.lcd.display("Mobile Backup", f"Case: {case_num}")

        # Wait for iOS device to be connected
        logger.info("Waiting for iOS device...")
        self.lcd.display("Waiting for", "iOS device...")

        timeout = 900  # 15 minutes
        start_time = time.time()
        ios_device = None

        while time.time() - start_time < timeout:
            try:
                # Detect iOS devices
                devices = self._detect_ios_devices()
                if devices:
                    ios_device = devices[0]
                    logger.info(f"iOS device detected: {ios_device.get('device_name', 'Unknown')}")
                    self.lcd.display("iOS Device", ios_device.get('device_name', 'Found')[:16])
                    break
            except Exception as e:
                logger.debug(f"iOS detection error: {e}")

            time.sleep(5)

        if not ios_device:
            error = "iOS device not detected within timeout period"
            logger.error(error)
            self.lcd.display("No iOS device", "Check connection")
            time.sleep(5)
            return

        # Build job_info for mobile extraction
        image_name = config.get('imager-config', {}).get('image_name', 'mobile_backup')
        job_info = {
            'job_id': job_id,
            'config': config,
            'mobile_extraction': {
                'udid': ios_device.get('udid'),
                'serial_number': ios_device.get('serial_number'),
                'device_name': ios_device.get('device_name'),
                'extraction_method': config.get('system', {}).get('extraction_method', 'logical'),
                'backup_encrypted': config.get('system', {}).get('backup_encrypted', False),
                'backup_password': config.get('system', {}).get('backup_password', ''),
            }
        }

        logger.info(f"Starting mobile extraction for {ios_device.get('device_name', 'Unknown')}")
        self.lcd.display("Extracting", ios_device.get('device_name', 'Device')[:16])

        # Use existing mobile extraction logic
        success = self._execute_mobile_extraction(job_info)

        if success:
            logger.info("Standalone mobile extraction completed successfully")
            self.lcd.display("Backup Complete", "Remove config")
        else:
            logger.error("Standalone mobile extraction failed")
            self.lcd.display("Backup Failed", "Remove config")

    def run(self):
        """Main agent loop."""
        logger.info("acquirepi Agent starting...")

        # Discover manager
        if not self.discover_manager():
            logger.error("Could not discover manager. Exiting.")
            return

        # Check if in standalone mode (no manager URL)
        standalone_mode = (self.manager_url is None)

        if standalone_mode:
            logger.info("Running in standalone mode - will execute job from USB config stick")
            self.run_standalone_mode()
            return

        # Register with manager
        is_approved = self.register()
        if not is_approved:
            logger.warning("Agent is not yet approved. Waiting for approval...")

        # Setup SSH key for manager access
        self.setup_ssh_key()

        # Main loop
        last_heartbeat = 0
        last_poll = 0
        last_lcd_update = 0
        last_mobile_check = 0
        MOBILE_CHECK_INTERVAL = 5  # Check for mobile devices every 5 seconds

        # Track connected devices for disconnect detection
        previously_connected_devices = set()  # Set of device serial numbers

        # On startup, do an initial scan to populate the tracking set
        # This prevents marking devices as disconnected on first scan
        try:
            initial_devices = self.detect_mobile_devices()
            for device in initial_devices:
                serial = device.get('serial_number')
                if serial:
                    previously_connected_devices.add(serial)
                    logger.info(f"Initial device scan: {device.get('device_name')} ({serial})")
        except Exception as e:
            logger.debug(f"Initial mobile device scan error: {e}")

        while True:
            try:
                current_time = time.time()

                # Retry registration if agent_id is missing (registration failed at startup)
                # This handles race conditions where manager wasn't ready when agent started
                if self.agent_id is None:
                    logger.warning("Agent ID is None - retrying registration...")
                    is_approved = self.register()
                    if not is_approved:
                        logger.warning("Agent registration still pending approval")

                # Send heartbeat
                if current_time - last_heartbeat >= HEARTBEAT_INTERVAL:
                    self.heartbeat()
                    last_heartbeat = current_time

                # Update LCD with ready status (every 30 seconds when idle)
                if not self.current_job and current_time - last_lcd_update >= 30:
                    self.lcd.show_status("online")
                    last_lcd_update = current_time

                # Check for mobile devices (every 5 seconds)
                if current_time - last_mobile_check >= MOBILE_CHECK_INTERVAL:
                    try:
                        devices = self.detect_mobile_devices()
                        current_device_serials = set()

                        # Register or update connected devices
                        for device in devices:
                            serial = device.get('serial_number')
                            if serial:
                                current_device_serials.add(serial)
                            self.register_mobile_device(device)

                        # Detect disconnections
                        disconnected_devices = previously_connected_devices - current_device_serials
                        for serial in disconnected_devices:
                            logger.info(f"Mobile device disconnected: {serial}")
                            # Notify manager of disconnection
                            try:
                                requests.post(
                                    f"{self.manager_url}/api/mobile-devices/disconnect_by_serial/",
                                    json={'serial_number': serial, 'agent_id': self.agent_id},
                                    timeout=5
                                )
                            except Exception as e:
                                logger.debug(f"Failed to notify disconnection: {e}")

                        # Update tracking set
                        previously_connected_devices = current_device_serials

                    except Exception as e:
                        logger.debug(f"Mobile device detection error: {e}")
                    last_mobile_check = current_time

                # Check for jobs (only if not currently executing)
                if not self.current_job and current_time - last_poll >= POLL_INTERVAL:
                    job_info = self.check_for_jobs()
                    if job_info:
                        self.execute_job(job_info)
                    last_poll = current_time

                time.sleep(1)

            except KeyboardInterrupt:
                logger.info("Agent stopped by user")
                break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                time.sleep(5)


if __name__ == '__main__':
    agent = Agent()
    agent.run()
