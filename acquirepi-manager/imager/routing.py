"""
WebSocket routing for imager app.
"""
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/job/(?P<job_id>\d+)/$', consumers.JobStatusConsumer.as_asgi()),
    re_path(r'ws/dashboard/$', consumers.DashboardConsumer.as_asgi()),
    re_path(r'ws/job-list/$', consumers.JobListConsumer.as_asgi()),
    re_path(r'ws/terminal/(?P<agent_id>\d+)/$', consumers.WebSSHConsumer.as_asgi()),
]
