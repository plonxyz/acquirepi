"""
Management command to monitor agent status and mark stale agents as offline.
Run this periodically via cron to trigger offline webhooks.
"""
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from imager.models import Agent
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Monitor agents and mark stale ones as offline (triggers webhooks)'

    def handle(self, *args, **options):
        # Find agents that should be online but haven't sent heartbeat
        agents = Agent.objects.filter(is_approved=True)

        offline_count = 0
        for agent in agents:
            # Check if agent should be marked offline
            if agent.status in ['online', 'imaging']:
                # Use same timeout logic as is_truly_online()
                timeout_minutes = 10 if agent.status == 'imaging' else 1.5
                cutoff = timezone.now() - timedelta(minutes=timeout_minutes)

                if agent.last_seen < cutoff:
                    # Agent is stale, mark as offline
                    self.stdout.write(
                        self.style.WARNING(
                            f'Marking agent {agent.hostname} as offline (last seen: {agent.last_seen})'
                        )
                    )
                    agent.mark_offline()
                    offline_count += 1

        if offline_count > 0:
            self.stdout.write(
                self.style.SUCCESS(f'Marked {offline_count} agent(s) as offline')
            )
        else:
            self.stdout.write(self.style.SUCCESS('All agents are online'))
