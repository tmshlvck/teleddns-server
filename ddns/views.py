"""
TeleDDNS Server - DDNS App Views
(C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from manager.signals import set_request_context, clear_request_context
from .services import (
    update_ddns_record,
    verify_user_password,
    extract_basic_auth_credentials,
    DDNSError,
    DDNSAuthenticationError,
    DDNSPermissionError,
    DDNSValidationError
)

logger = logging.getLogger(__name__)


def authenticate_ddns_request(request):
    """
    Authenticate a DDNS request using either Token or Basic Auth.

    Returns:
        User object if authenticated, None otherwise
    """
    # First check if user is already authenticated via token
    if request.user and request.user.is_authenticated:
        return request.user

    # Try HTTP Basic Auth
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    username, password = extract_basic_auth_credentials(auth_header)

    if username and password:
        user = verify_user_password(username, password)
        if user:
            return user

    return None


def get_client_ip(request):
    """
    Get the client's IP address from the request.

    Handles X-Forwarded-For and X-Real-IP headers for proxy setups.
    """
    # Check for forwarded IP first
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs, take the first one
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        # Check X-Real-IP header
        ip = request.META.get('HTTP_X_REAL_IP')
        if not ip:
            # Fall back to REMOTE_ADDR
            ip = request.META.get('REMOTE_ADDR')

    return ip


@csrf_exempt
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def ddns_update(request):
    """
    DDNS update endpoint that supports both GET and POST methods.

    Parameters:
    - domain or hostname: The domain name to update
    - myip or ip: The IP address to set (optional, defaults to client IP)
    - username: Username for Basic Auth (if not using token)
    - password: Password for Basic Auth (if not using token)

    Returns:
    - 200 OK: Update successful
    - 400 Bad Request: Invalid parameters
    - 401 Unauthorized: Authentication failed
    - 403 Forbidden: Permission denied
    - 404 Not Found: Zone not found
    - 500 Internal Server Error: Server error
    """
    try:
        # Authenticate the request
        user = authenticate_ddns_request(request)
        if not user:
            logger.warning(f"DDNS authentication failed from {get_client_ip(request)}")
            return Response(
                {'error': 'Authentication required'},
                status=status.HTTP_401_UNAUTHORIZED,
                headers={'WWW-Authenticate': 'Basic realm="DDNS Update"'}
            )

        # Set audit context
        set_request_context(user=user, source='DDNS')

        # Get parameters from either GET or POST
        if request.method == 'GET':
            params = request.GET
        else:
            params = request.data if hasattr(request, 'data') else request.POST

        # Extract domain name (support both 'domain' and 'hostname' parameters)
        domain_name = params.get('domain') or params.get('hostname')
        if not domain_name:
            return Response(
                {'error': 'Missing required parameter: domain or hostname'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Extract IP address (support both 'myip' and 'ip' parameters)
        ip_address = params.get('myip') or params.get('ip')
        if not ip_address:
            # Use client's IP address as default
            ip_address = get_client_ip(request)
            if not ip_address:
                return Response(
                    {'error': 'Could not determine IP address'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Perform the update
        logger.info(
            f"DDNS update request from {user.username} for {domain_name} -> {ip_address} "
            f"(client IP: {get_client_ip(request)})"
        )

        changed, message, zone = update_ddns_record(
            user=user,
            domain_name=domain_name,
            ip_address=ip_address,
            source='DDNS'
        )

        # Log the result
        if changed:
            logger.info(f"DDNS update successful: {message}")
        else:
            logger.info(f"DDNS no change needed: {message}")

        # Return response
        response_data = {
            'success': True,
            'message': message,
            'domain': domain_name,
            'ip': ip_address,
            'zone': zone.origin,
            'changed': changed
        }

        return Response(response_data, status=status.HTTP_200_OK)

    except DDNSValidationError as e:
        logger.warning(f"DDNS validation error: {str(e)}")
        return Response(
            {'error': str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )

    except DDNSPermissionError as e:
        logger.warning(f"DDNS permission error: {str(e)}")
        return Response(
            {'error': str(e)},
            status=status.HTTP_403_FORBIDDEN
        )

    except DDNSAuthenticationError as e:
        logger.warning(f"DDNS authentication error: {str(e)}")
        return Response(
            {'error': str(e)},
            status=status.HTTP_401_UNAUTHORIZED,
            headers={'WWW-Authenticate': 'Basic realm="DDNS Update"'}
        )

    except DDNSError as e:
        logger.error(f"DDNS error: {str(e)}")
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    except Exception as e:
        logger.exception(f"Unexpected error in DDNS update")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    finally:
        # Clear audit context
        clear_request_context()


@csrf_exempt
@require_http_methods(['GET'])
def ddns_status(request):
    """
    Simple status endpoint to check if DDNS service is running.

    Returns:
    - 200 OK: Service is running
    """
    return JsonResponse({
        'status': 'ok',
        'service': 'TeleDDNS Server',
        'version': '2.0.0'
    })


# Alternative simple response format for compatibility
@csrf_exempt
@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def ddns_update_simple(request):
    """
    Simplified DDNS update endpoint that returns plain text responses.

    This endpoint is designed for compatibility with simple DDNS clients
    that expect plain text responses instead of JSON.
    """
    try:
        # Use the same logic as the main update endpoint
        user = authenticate_ddns_request(request)
        if not user:
            return HttpResponse(
                'badauth',
                status=401,
                content_type='text/plain'
            )

        # Set audit context
        set_request_context(user=user, source='DDNS')

        # Get parameters
        if request.method == 'GET':
            params = request.GET
        else:
            params = request.data if hasattr(request, 'data') else request.POST

        domain_name = params.get('domain') or params.get('hostname')
        if not domain_name:
            return HttpResponse(
                'notfqdn',
                status=400,
                content_type='text/plain'
            )

        ip_address = params.get('myip') or params.get('ip')
        if not ip_address:
            ip_address = get_client_ip(request)

        # Perform update
        changed, message, zone = update_ddns_record(
            user=user,
            domain_name=domain_name,
            ip_address=ip_address,
            source='DDNS'
        )

        # Return simple response
        if changed:
            return HttpResponse(
                f'good {ip_address}',
                content_type='text/plain'
            )
        else:
            return HttpResponse(
                f'nochg {ip_address}',
                content_type='text/plain'
            )

    except DDNSValidationError:
        return HttpResponse(
            'notfqdn',
            status=400,
            content_type='text/plain'
        )

    except DDNSPermissionError:
        return HttpResponse(
            'nohost',
            status=403,
            content_type='text/plain'
        )

    except Exception:
        logger.exception("Error in simple DDNS update")
        return HttpResponse(
            '911',
            status=500,
            content_type='text/plain'
        )

    finally:
        clear_request_context()
