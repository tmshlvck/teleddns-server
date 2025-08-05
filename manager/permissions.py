"""
TeleDDNS Server - Manager App Permissions
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

from rest_framework import permissions
from django.contrib.auth.models import User, Group


class IsOwnerOrInGroup(permissions.BasePermission):
    """
    Custom permission to only allow owners or group members to access objects.

    - Superusers have unrestricted access
    - Object owners have full access
    - Group members have access if they belong to the object's group
    - For list views, users see only objects they have access to (filtered in viewset)
    """

    def has_permission(self, request, view):
        """
        Check if user has permission to access the view.
        For list/create operations.
        """
        # Authenticated users can access the view
        # Actual filtering happens in get_queryset
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission to access a specific object.
        For retrieve/update/destroy operations.
        """
        # Superusers have unrestricted access
        if request.user.is_superuser:
            return True

        # Check if the object has an owner field
        if hasattr(obj, 'owner'):
            # Owner has full access
            if obj.owner == request.user:
                return True

        # Check if the object has a group field
        if hasattr(obj, 'group'):
            # Group members have access
            if obj.group in request.user.groups.all():
                return True

        # For Zone objects, also check if user has access through any related records
        if obj.__class__.__name__ == 'Zone':
            # Import here to avoid circular imports
            from .models import RR_MODELS

            # Check if user owns any records in this zone
            for rr_model in RR_MODELS:
                if rr_model.objects.filter(
                    zone=obj,
                    owner=request.user
                ).exists():
                    return True

                # Check if user's groups have any records in this zone
                user_groups = request.user.groups.all()
                if user_groups and rr_model.objects.filter(
                    zone=obj,
                    group__in=user_groups
                ).exists():
                    return True

        return False


class IsAuthenticatedOrDDNS(permissions.BasePermission):
    """
    Custom permission for DDNS endpoints.
    Allows both token authentication and HTTP Basic Auth.
    """

    def has_permission(self, request, view):
        """
        DDNS endpoints require either:
        - Token authentication
        - HTTP Basic authentication (handled by the view)
        """
        # If user is authenticated via token, allow access
        if request.user and request.user.is_authenticated:
            return True

        # If HTTP Basic Auth is provided, the view will handle validation
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Basic '):
            return True

        return False


class IsSuperuserOrReadOnly(permissions.BasePermission):
    """
    Custom permission for Server model.
    Only superusers can create/update/delete servers.
    Regular users can only view servers.
    """

    def has_permission(self, request, view):
        """
        List and create permissions.
        """
        if request.method in permissions.SAFE_METHODS:
            # Allow read access for authenticated users
            return request.user and request.user.is_authenticated
        else:
            # Only superusers can create
            return request.user and request.user.is_superuser

    def has_object_permission(self, request, view, obj):
        """
        Object level permissions.
        """
        if request.method in permissions.SAFE_METHODS:
            # Allow read access for authenticated users
            return request.user and request.user.is_authenticated
        else:
            # Only superusers can update/delete
            return request.user and request.user.is_superuser


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    Everyone can read.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated

        # Write permissions are only allowed to the owner
        return obj.owner == request.user or request.user.is_superuser
