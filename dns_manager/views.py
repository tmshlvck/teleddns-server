from django.shortcuts import render
from django.http import JsonResponse
from django.conf import settings
from datetime import datetime, timezone, timedelta
from .models import Server, MasterZone


def health_check(request):
    """
    Health check endpoint that reports on backend sync status.
    
    Returns:
    - OK: No dirty servers/zones
    - OK: All dirty servers/zones have been synced within BACKEND_SYNC_PERIOD * 3
    - WARN: Dirty items exist but within 7200 seconds threshold
    - ERR: Otherwise
    """
    now = datetime.now(timezone.utc)
    sync_period = getattr(settings, 'BACKEND_SYNC_PERIOD', 300)
    warn_threshold = 7200  # 2 hours as per specs
    
    # Check dirty servers
    dirty_servers = Server.objects.filter(config_dirty=True, is_active=True)
    
    # Check dirty zones  
    dirty_zones = MasterZone.objects.filter(
        content_dirty=True,
        master_server__is_active=True
    )
    
    # If no dirty items, return OK
    if not dirty_servers.exists() and not dirty_zones.exists():
        return JsonResponse({'status': 'OK', 'message': 'No dirty servers or zones'})
    
    # Check if all dirty items have been synced recently
    max_age_ok = timedelta(seconds=sync_period * 3)
    max_age_warn = timedelta(seconds=warn_threshold)
    
    all_within_ok_threshold = True
    all_within_warn_threshold = True
    
    # Check server sync times
    for server in dirty_servers:
        if not server.last_config_sync:
            # Never synced
            all_within_ok_threshold = False
            all_within_warn_threshold = False
            break
        time_since_sync = now - server.last_config_sync
        if time_since_sync > max_age_ok:
            all_within_ok_threshold = False
        if time_since_sync > max_age_warn:
            all_within_warn_threshold = False
    
    # Check zone sync times
    for zone in dirty_zones:
        if not zone.last_content_sync:
            # Never synced
            all_within_ok_threshold = False
            all_within_warn_threshold = False
            break
        time_since_sync = now - zone.last_content_sync
        if time_since_sync > max_age_ok:
            all_within_ok_threshold = False
        if time_since_sync > max_age_warn:
            all_within_warn_threshold = False
    
    # Determine status
    dirty_server_count = dirty_servers.count()
    dirty_zone_count = dirty_zones.count()
    
    if all_within_ok_threshold:
        return JsonResponse({
            'status': 'OK',
            'message': f'All dirty items synced within acceptable threshold (dirty servers: {dirty_server_count}, dirty zones: {dirty_zone_count})'
        })
    elif all_within_warn_threshold:
        return JsonResponse({
            'status': 'WARN', 
            'message': f'Dirty items exist but within warning threshold (dirty servers: {dirty_server_count}, dirty zones: {dirty_zone_count})'
        })
    else:
        return JsonResponse({
            'status': 'ERR',
            'message': f'Dirty items have not been synced recently (dirty servers: {dirty_server_count}, dirty zones: {dirty_zone_count})'
        })


def robots_txt(request):
    """Return robots.txt content."""
    from django.http import HttpResponse
    return HttpResponse("User-agent: *\nDisallow: /", content_type="text/plain")
