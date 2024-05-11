# permissions.py
from rest_framework import permissions

class DenyAllPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        # Deny access to all users
        return False