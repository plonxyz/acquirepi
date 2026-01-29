"""
WebSocket consumers for real-time updates.
"""
import json
import asyncio
import paramiko
import os
import uuid
from datetime import datetime
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone


class JobStatusConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for job status updates."""

    async def connect(self):
        """Connect to WebSocket."""
        self.job_id = self.scope['url_route']['kwargs']['job_id']
        self.job_group_name = f'job_{self.job_id}'

        # Join job group
        await self.channel_layer.group_add(
            self.job_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        """Disconnect from WebSocket."""
        # Leave job group
        await self.channel_layer.group_discard(
            self.job_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        """Receive message from WebSocket."""
        # We don't expect messages from client, but handle gracefully
        pass

    async def job_update(self, event):
        """Receive job update from channel layer and send to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'job_update',
            'job': event['job']
        }))

    async def job_log(self, event):
        """Receive job log from channel layer and send to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'job_log',
            'log': event['log']
        }))


class DashboardConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for dashboard updates."""

    async def connect(self):
        """Connect to WebSocket."""
        self.group_name = 'dashboard'

        # Join dashboard group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        """Disconnect from WebSocket."""
        # Leave dashboard group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        """Receive message from WebSocket."""
        pass

    async def dashboard_update(self, event):
        """Receive dashboard update from channel layer and send to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'dashboard_update',
            'data': event['data']
        }))

    async def agent_update(self, event):
        """Receive agent update from channel layer and send to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'agent_update',
            'agent': event['agent']
        }))

    async def job_update(self, event):
        """Receive job update from channel layer and send to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'job_update',
            'job': event['job']
        }))


class JobListConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for job list updates."""

    async def connect(self):
        """Connect to WebSocket."""
        self.group_name = 'job_list'

        # Join job list group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        """Disconnect from WebSocket."""
        # Leave job list group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        """Receive message from WebSocket."""
        pass

    async def job_list_update(self, event):
        """Receive job list update from channel layer and send to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'job_list_update',
            'job': event['job']
        }))


class WebSSHConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for SSH terminal access to agents."""

    async def connect(self):
        """Connect to WebSocket and establish SSH connection."""
        self.agent_id = self.scope['url_route']['kwargs']['agent_id']
        self.user = self.scope['user']

        # Check if user is authenticated
        if not self.user.is_authenticated:
            await self.close(code=4001)
            return

        # Get agent details
        agent = await self.get_agent(self.agent_id)
        if not agent:
            await self.close(code=4004)
            return

        self.agent = agent
        self.ssh_client = None
        self.ssh_channel = None
        self.session_id = str(uuid.uuid4())
        self.transcript = []

        # Create session record
        self.session = await self.create_session_record()

        # Log the shell access
        await self.log_audit()

        await self.accept()

        # Attempt SSH connection
        try:
            await self.establish_ssh_connection()
        except Exception as e:
            error_msg = f"SSH connection failed: {str(e)}\r\n"
            await self.send(text_data=json.dumps({
                'type': 'output',
                'data': error_msg
            }))
            await self.close()

    async def disconnect(self, close_code):
        """Disconnect from WebSocket and close SSH connection."""
        # Close SSH channel and client
        if self.ssh_channel:
            try:
                self.ssh_channel.close()
            except:
                pass

        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass

        # Save transcript and close session
        if hasattr(self, 'session'):
            await self.save_transcript()
            await self.close_session()

    async def receive(self, text_data):
        """Receive message from WebSocket (user input)."""
        try:
            data = json.loads(text_data)
            msg_type = data.get('type')

            if msg_type == 'input':
                # User typed something
                input_data = data.get('data', '')
                if self.ssh_channel and not self.ssh_channel.closed:
                    # Send to SSH channel
                    await asyncio.get_event_loop().run_in_executor(
                        None, self.ssh_channel.send, input_data.encode('utf-8')
                    )

                    # Log to transcript
                    self.transcript.append({
                        'timestamp': datetime.now().isoformat(),
                        'type': 'input',
                        'data': input_data
                    })

            elif msg_type == 'resize':
                # Terminal resize
                cols = data.get('cols', 80)
                rows = data.get('rows', 24)
                if self.ssh_channel and not self.ssh_channel.closed:
                    await asyncio.get_event_loop().run_in_executor(
                        None, self.ssh_channel.resize_pty, cols, rows
                    )

        except Exception as e:
            print(f"Error in receive: {e}")

    async def establish_ssh_connection(self):
        """Establish SSH connection to the agent."""
        # Get SSH credentials
        ssh_username = await self.get_ssh_username()
        ssh_password = await self.get_ssh_password()
        ssh_key_path = await self.get_ssh_key_path()

        # Create SSH client
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Connect to agent
        connect_kwargs = {
            'hostname': self.agent['ip_address'],
            'username': ssh_username,
            'timeout': 10,
        }

        if ssh_key_path and os.path.exists(ssh_key_path):
            connect_kwargs['key_filename'] = ssh_key_path
        elif ssh_password:
            connect_kwargs['password'] = ssh_password
        else:
            # Default to 'raspberry' for Raspberry Pi
            connect_kwargs['password'] = 'raspberry'

        # Run connection in executor (blocking operation)
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: self.ssh_client.connect(**connect_kwargs)
        )

        # Open SSH channel with PTY
        self.ssh_channel = self.ssh_client.invoke_shell(term='xterm-256color', width=80, height=24)

        # Start reading output from SSH
        asyncio.create_task(self.read_ssh_output())

        # Send welcome message
        welcome_msg = f"Connected to {self.agent['hostname']} ({self.agent['ip_address']})\r\n"
        await self.send(text_data=json.dumps({
            'type': 'output',
            'data': welcome_msg
        }))

    async def read_ssh_output(self):
        """Read output from SSH channel and send to WebSocket."""
        try:
            while not self.ssh_channel.closed:
                if self.ssh_channel.recv_ready():
                    # Read data from SSH channel
                    data = await asyncio.get_event_loop().run_in_executor(
                        None, self.ssh_channel.recv, 4096
                    )

                    if data:
                        output = data.decode('utf-8', errors='replace')

                        # Send to WebSocket
                        await self.send(text_data=json.dumps({
                            'type': 'output',
                            'data': output
                        }))

                        # Log to transcript
                        self.transcript.append({
                            'timestamp': datetime.now().isoformat(),
                            'type': 'output',
                            'data': output
                        })
                else:
                    # Small delay to prevent CPU spinning
                    await asyncio.sleep(0.01)

        except Exception as e:
            print(f"Error reading SSH output: {e}")
            await self.close()

    @database_sync_to_async
    def get_agent(self, agent_id):
        """Get agent from database."""
        from .models import Agent
        try:
            agent = Agent.objects.get(id=agent_id)
            return {
                'id': agent.id,
                'hostname': agent.hostname,
                'ip_address': agent.ip_address,
                'ssh_username': getattr(agent, 'ssh_username', 'pi'),
                'ssh_password': getattr(agent, 'ssh_password', None),
                'ssh_key_path': getattr(agent, 'ssh_key_path', None),
            }
        except Agent.DoesNotExist:
            return None

    @database_sync_to_async
    def get_ssh_username(self):
        """Get SSH username for agent."""
        return self.agent.get('ssh_username', 'pi')

    @database_sync_to_async
    def get_ssh_password(self):
        """Get SSH password for agent."""
        return self.agent.get('ssh_password')

    @database_sync_to_async
    def get_ssh_key_path(self):
        """Get SSH key path for agent."""
        return self.agent.get('ssh_key_path')

    @database_sync_to_async
    def create_session_record(self):
        """Create a session record in the database."""
        from .models import RemoteShellSession, Agent

        agent = Agent.objects.get(id=self.agent_id)

        # Get IP address from scope
        client_ip = None
        for header_name, header_value in self.scope.get('headers', []):
            if header_name == b'x-forwarded-for':
                client_ip = header_value.decode().split(',')[0].strip()
                break

        if not client_ip:
            # Try to get from scope directly
            client = self.scope.get('client', ['unknown', 0])
            client_ip = client[0] if client[0] != 'unknown' else '127.0.0.1'

        session = RemoteShellSession.objects.create(
            session_id=self.session_id,
            agent=agent,
            user=self.user,
            ip_address=client_ip,
            user_agent=dict(self.scope.get('headers', {})).get(b'user-agent', b'').decode()
        )

        return session

    @database_sync_to_async
    def log_audit(self):
        """Log shell access to audit log."""
        from .models import AuditLog, Agent

        agent = Agent.objects.get(id=self.agent_id)

        AuditLog.log_action(
            user=self.user,
            action='shell_access',
            description=f"Remote shell access to agent {agent.hostname} ({agent.ip_address})",
            content_object=agent,
            extra_data={
                'session_id': self.session_id,
                'agent_id': self.agent_id,
                'agent_hostname': agent.hostname,
                'agent_ip': agent.ip_address,
            }
        )

    @database_sync_to_async
    def save_transcript(self):
        """Save session transcript to file."""
        from .models import RemoteShellSession
        import json

        # Create transcript directory if it doesn't exist
        transcript_dir = '/opt/acquirepi-manager/logs/shell_transcripts'
        os.makedirs(transcript_dir, exist_ok=True)

        # Save transcript to file
        transcript_filename = f"{self.session_id}.json"
        transcript_path = os.path.join(transcript_dir, transcript_filename)

        try:
            with open(transcript_path, 'w') as f:
                json.dump(self.transcript, f, indent=2)

            # Update session record
            session = RemoteShellSession.objects.get(session_id=self.session_id)
            session.transcript_path = transcript_path
            session.save()
        except Exception as e:
            print(f"Error saving transcript: {e}")

    @database_sync_to_async
    def close_session(self):
        """Close the session record."""
        from .models import RemoteShellSession

        try:
            session = RemoteShellSession.objects.get(session_id=self.session_id)
            session.close()
        except RemoteShellSession.DoesNotExist:
            pass
