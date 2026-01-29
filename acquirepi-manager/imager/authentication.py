"""
Custom authentication classes for acquirepi Manager API.
"""
from rest_framework import authentication
from rest_framework import exceptions
from .models import Agent


class AgentTokenAuthentication(authentication.BaseAuthentication):
    """
    Token-based authentication for agents.

    Clients should authenticate by passing the token in the "Authorization" HTTP header,
    prepended with the string "Bearer ".  For example:

        Authorization: Bearer <token>
    """

    keyword = 'Bearer'

    def authenticate(self, request):
        """Authenticate the request and return a two-tuple of (agent, token)."""
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()

        if not auth or auth[0].lower() != self.keyword.lower():
            return None

        if len(auth) == 1:
            msg = 'Invalid token header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid token header. Token string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1]
        except UnicodeError:
            msg = 'Invalid token header. Token string should not contain invalid characters.'
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, key):
        """Attempt to find and return agent with the given token."""
        try:
            agent = Agent.objects.get(api_token=key, is_approved=True)
        except Agent.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid token or agent not approved.')

        return (agent, key)

    def authenticate_header(self, request):
        """Return the authentication header for 401 responses."""
        return self.keyword


class AgentOrTokenAuthentication(authentication.BaseAuthentication):
    """
    Allow both token authentication and MAC address authentication.
    This is for backward compatibility during migration.

    First tries token authentication, then falls back to MAC address in query params.
    """

    def authenticate(self, request):
        """Try token auth first, then MAC address auth."""
        # Try token authentication first
        token_auth = AgentTokenAuthentication()
        result = token_auth.authenticate(request)
        if result is not None:
            return result

        # Fall back to MAC address authentication (backward compatibility)
        mac_address = request.query_params.get('mac_address') or request.data.get('mac_address')

        if not mac_address:
            return None  # Let other auth methods try

        try:
            agent = Agent.objects.get(mac_address=mac_address, is_approved=True)
            return (agent, None)
        except Agent.DoesNotExist:
            return None  # Don't raise exception, let other auth methods try

    def authenticate_header(self, request):
        """Return the authentication header for 401 responses."""
        return 'Bearer'
