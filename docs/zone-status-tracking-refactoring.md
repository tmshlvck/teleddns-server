# Zone Status Tracking Refactoring

## Overview

This document describes the refactoring of the zone status tracking system in TeleDDNS Server. The previous implementation used a single `is_dirty` flag which was too simplistic to handle the different synchronization scenarios and per-server tracking properly.

## Problem Statement

The original `is_dirty` flag had several critical limitations:

1. **No distinction between content and configuration changes**: The system couldn't differentiate between:
   - Changes to resource records (requiring zone content update)
   - Changes to zone configuration (requiring server config reload)

2. **No per-server tracking**: When a zone was served by multiple servers:
   - Couldn't track which servers had been successfully synchronized
   - Partial sync failures weren't handled properly
   - All servers were marked clean even if some failed

3. **Limited visibility**: The binary dirty/clean state provided no insight into:
   - When changes were made
   - Which specific servers need updates
   - How long changes have been pending

## New Status Tracking System

### Zone Model Fields

The `Zone` model now includes:

- **`content_dirty`** (boolean): Indicates zone content (resource records) has pending changes
- **`content_dirty_since`** (datetime, nullable): Timestamp when content was marked dirty
- **`master_config_dirty`** (boolean): Indicates master server configuration has changed
- **`master_config_dirty_since`** (datetime, nullable): Timestamp when master config was marked dirty

### SlaveOnlyZone Model Fields

The `SlaveOnlyZone` model has been simplified - status tracking is now entirely handled through the per-server status tables.

### Per-Server Status Tracking

Two new models track synchronization status for each zone-server combination:

#### ZoneServerStatus Model

Tracks the relationship between a Zone and its servers (both master and slaves):

- **`zone`** (ForeignKey): Reference to the Zone
- **`server`** (ForeignKey): Reference to the Server
- **`config_dirty`** (boolean): Server configuration for this zone needs update
- **`config_dirty_since`** (datetime, nullable): When config was marked dirty
- **`last_sync_time`** (datetime, nullable): Last successful synchronization time

#### SlaveOnlyZoneServerStatus Model

Tracks the relationship between a SlaveOnlyZone and its slave servers:

- **`zone`** (ForeignKey): Reference to the SlaveOnlyZone
- **`server`** (ForeignKey): Reference to the Server
- **`config_dirty`** (boolean): Server configuration for this zone needs update
- **`config_dirty_since`** (datetime, nullable): When config was marked dirty
- **`last_sync_time`** (datetime, nullable): Last successful synchronization time

## Synchronization Scenarios

### 1. Content Changes (Master Zones)

When resource records are modified:
- `content_dirty` is set to `True` on the Zone
- `content_dirty_since` is set to current timestamp
- Zone serial is incremented
- Zone content is pushed to master server during sync
- On successful sync: `content_dirty` is cleared
- Slave servers receive updates via AXFR from master

### 2. Master Server Configuration Changes

When a zone's master server is changed:
- `master_config_dirty` is set to `True` on the Zone
- `master_config_dirty_since` is set to current timestamp
- Master server configuration is regenerated during sync
- On successful sync: `master_config_dirty` is cleared

### 3. Slave Server Configuration Changes

When zone's slave servers are added/removed:
- `ZoneServerStatus` records are created/updated
- `config_dirty` is set to `True` for affected servers
- `config_dirty_since` is set to current timestamp
- Each server's configuration is updated independently
- On successful sync: `config_dirty` is cleared for that specific server

### 4. Partial Sync Failures

The per-server tracking enables proper handling of partial failures:
- If sync fails for server A but succeeds for server B:
  - Server A's `config_dirty` remains `True`
  - Server B's `config_dirty` is cleared and `last_sync_time` updated
- Next sync attempt will only update servers that still have `config_dirty = True`

## Implementation Details

### Signals

The following signals trigger status updates:

1. **Resource Record Changes**: 
   - Post-save and post-delete signals on all RR models
   - Sets `content_dirty = True` and `content_dirty_since`
   - Increments serial

2. **Master Server Changes**:
   - Pre-save signal detects master_server changes
   - Sets `master_config_dirty = True` and `master_config_dirty_since`

3. **Slave Server Changes**:
   - M2M changed signal for Zone.slave_servers
   - Creates/updates ZoneServerStatus records
   - Sets `config_dirty = True` for affected servers

4. **SlaveOnlyZone Changes**:
   - Pre-save signal detects external_master changes
   - M2M changed signal for slave_servers
   - Creates/updates SlaveOnlyZoneServerStatus records

### Admin Interface

The admin interface has been updated to:

1. **Status Indicator**: Shows colored status based on sync state:
   - 🟢 Green: Synchronized
   - 🟠 Orange: Pending Sync (content/config changes)
   - Also indicates if slave servers need sync

2. **Actions**:
   - `mark_content_dirty`: Mark zones as having content changes
   - `mark_config_dirty`: Mark master config as dirty
   - `mark_clean`: Clear all dirty flags (including per-server statuses)

3. **Filters**: Filter by content_dirty and master_config_dirty

### API Changes

#### Zone Serializer

The Zone API now includes:
```json
{
  "id": 1,
  "origin": "example.com.",
  "content_dirty": false,
  "content_dirty_since": null,
  "master_config_dirty": false,
  "master_config_dirty_since": null,
  // ... other fields
}
```

#### SlaveOnlyZone Serializer

The SlaveOnlyZone API no longer includes dirty flags directly - status is tracked per-server.

### Management Commands

The `sync_zones` command has been updated to:

1. Check both zone-level and per-server dirty flags
2. Only sync servers that need updates
3. Track per-server sync success
4. Support force sync regardless of dirty state

Examples:
```bash
# Sync all dirty zones and servers
python manage.py sync_zones

# Force sync specific zone
python manage.py sync_zones --zone example.com. --force

# Sync zones for specific server (only dirty ones)
python manage.py sync_zones --server ns1.example.com
```

## Migration Guide

### Database Migration

The migrations handle:

1. **Schema Changes** (`0006_add_per_server_status_tracking`):
   - Removes old status tracking fields
   - Adds new timestamp fields
   - Creates ZoneServerStatus and SlaveOnlyZoneServerStatus tables

2. **Data Migration** (`0007_populate_server_status_tables`):
   - Creates status records for all existing zone-server relationships
   - Initializes with clean state (config_dirty = False)

### Code Updates Required

If you have custom code that references the old tracking system:

```python
# Old code
if zone.is_dirty:
    sync_zone(zone)

# New code - check specific dirty flags
if zone.content_dirty or zone.master_config_dirty:
    sync_zone_content(zone)

# Check if any slave servers need sync
if zone.server_statuses.filter(config_dirty=True).exists():
    sync_slave_configs(zone)

# For slave-only zones
if zone.server_statuses.filter(config_dirty=True).exists():
    sync_slave_only_zone(zone)
```

## Benefits

1. **Accurate Per-Server Tracking**: Each server's sync status is tracked independently
2. **Partial Failure Handling**: Failed servers can be retried without re-syncing successful ones
3. **Better Performance**: Only sync what's actually needed for each server
4. **Clear Timestamps**: Know exactly when changes were made
5. **Granular Control**: Different types of changes handled appropriately

## Design Decisions

### Why No last_sync_success or last_sync_error?

Based on feedback, we simplified the design by:
- Removing `last_sync_success` and `last_sync_error` fields
- Keeping only `last_sync_time` which is updated only on successful sync
- Dirty flags remain set on failure, indicating retry is needed
- This simplifies the data model while maintaining all necessary functionality

### Why Separate Tables for Per-Server Status?

- Allows true many-to-many tracking with status
- Scales well as servers are added/removed
- Avoids complex JSON fields or denormalization
- Enables efficient queries for dirty zones per server

## Future Enhancements

Potential future improvements:

1. **Sync Queue**: Priority queue for zone synchronization
2. **Retry Policies**: Configurable retry intervals based on failure count
3. **Sync History**: Separate audit table for sync attempts
4. **Health Metrics**: Dashboard showing per-server synchronization health
5. **Bulk Operations**: Optimize sync for multiple zones on same server