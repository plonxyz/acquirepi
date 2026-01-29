"""
Django management command to advertise the manager service via mDNS.
"""
from django.core.management.base import BaseCommand
from django.conf import settings
from zeroconf import ServiceInfo, Zeroconf
import socket
import time


class Command(BaseCommand):
    help = 'Advertise acquirepi manager service via mDNS'

    def get_all_interface_ips(self):
        """Get all IPv4 addresses from all non-loopback interfaces."""
        addresses = []

        try:
            import netifaces
            for interface in netifaces.interfaces():
                if interface == 'lo':
                    continue
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr_info in addrs[netifaces.AF_INET]:
                        ip = addr_info.get('addr')
                        if ip and not ip.startswith('127.'):
                            addresses.append(ip)
                            self.stdout.write(
                                self.style.SUCCESS(f'Found IP {ip} on interface {interface}')
                            )
        except ImportError:
            self.stdout.write(self.style.WARNING(
                'netifaces not available, falling back to socket method'
            ))
            # Fallback: try socket trick
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith('127.'):
                    addresses.append(ip)
            except Exception:
                pass

        return addresses

    def handle(self, *args, **options):
        """Run mDNS service advertisement."""
        self.stdout.write(self.style.SUCCESS('Starting mDNS service advertisement...'))

        # Wait for network interfaces to come up (retry up to 30 seconds)
        addresses = []
        max_retries = 30
        for attempt in range(max_retries):
            addresses = self.get_all_interface_ips()
            if addresses:
                break
            self.stdout.write(self.style.WARNING(
                f'No network interfaces found, retrying... ({attempt + 1}/{max_retries})'
            ))
            time.sleep(1)

        if not addresses:
            self.stdout.write(self.style.ERROR(
                'No network interfaces found after retries. Exiting.'
            ))
            return

        # Service configuration
        service_type = settings.MDNS_SERVICE_TYPE
        service_name = f"{settings.MDNS_SERVICE_NAME}.{service_type}"
        port = settings.MDNS_PORT

        # Convert IP strings to packed addresses
        packed_addresses = [socket.inet_aton(ip) for ip in addresses]

        # Create service info with all addresses
        info = ServiceInfo(
            service_type,
            service_name,
            addresses=packed_addresses,
            port=port,
            properties={
                'version': '1.0',
                'api': '/api/',
            },
            server=f"{socket.gethostname()}.local."
        )

        zeroconf = Zeroconf()

        try:
            zeroconf.register_service(info)
            self.stdout.write(
                self.style.SUCCESS(
                    f'mDNS service registered: {service_name} on {", ".join(addresses)}:{port}'
                )
            )

            # Keep the service running
            self.stdout.write('Press Ctrl+C to stop...')
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nStopping mDNS service...'))
        finally:
            zeroconf.unregister_service(info)
            zeroconf.close()
            self.stdout.write(self.style.SUCCESS('mDNS service stopped.'))
