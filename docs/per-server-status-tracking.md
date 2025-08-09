# Per-Server Zone Status Tracking

## Overview

The per-server status tracking system ensures that each DNS server's synchronization state is tracked independently. This allows for proper handling of partial sync failures and efficient retry mechanisms.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                              Zone                               │
│  - content_dirty: bool                                          │
│  - content_dirty_since: datetime                                │
│  - master_config_dirty: bool                                    │
│  - master_config_dirty_since: datetime                          │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  │
        ┌─────────────────────────┴─────────────────────────┐
        │                                                   │
        ▼                                                   ▼
┌───────────────────┐                             ┌───────────────────┐
│  Master Server    │                             │   Slave Servers   │
│                   │                             │                   │
│  ns1.example.com  │                             │  ns2.example.com  │
└───────────────────┘                             │  ns3.example.com  │
        │                                         └───────────────────┘
        │                                                   │
        │                                                   │
        ▼                                                   ▼
┌───────────────────────────────────┐     ┌───────────────────────────────────┐
│      ZoneServerStatus             │     │      ZoneServerStatus             │
│  - zone: Zone                     │     │  - zone: Zone                     │
│  - server: ns1.example.com        │     │  - server: ns2/ns3.example.com    │
│  - config_dirty: bool             │     │  - config_dirty: bool             │
│  - config_dirty_since: datetime   │     │  - config_dirty_since: datetime   │
│  - last_sync_time: datetime       │     │  - last_sync_time: datetime       │
└───────────────────────────────────┘     └───────────────────────────────────┘
```

## Status Tracking Scenarios

### 1. Resource Record Change

When a resource record (A, AAAA, CNAME, etc.) is modified:

```
User modifies A record
         │
         ▼
Signal triggers
         │
         ├─► Zone.content_dirty = True
         ├─► Zone.content_dirty_since = now()
         └─► Zone serial incremented
         
Sync process:
         │
         ├─► Push zone content to master server
         │   └─► Success: Zone.content_dirty = False
         │                Zone.content_dirty_since = None
         │
         └─► Slave servers pull via AXFR (no direct push needed)
```

### 2. Master Server Change

When a zone's master server is changed:

```
Zone.master_server changed from ns1 to ns4
         │
         ▼
Signal triggers
         │
         ├─► Zone.master_config_dirty = True
         └─► Zone.master_config_dirty_since = now()
         
Sync process:
         │
         ├─► Update ns4 configuration
         ├─► Reload ns4
         │   └─► Success: Zone.master_config_dirty = False
         │                Zone.master_config_dirty_since = None
         │                ZoneServerStatus(zone, ns4).last_sync_time = now()
         │
         └─► (Old master ns1 would need manual cleanup)
```

### 3. Slave Server Addition/Removal

When slave servers are added or removed:

```
Zone.slave_servers.add(ns3)
         │
         ▼
M2M signal triggers
         │
         └─► ZoneServerStatus.objects.get_or_create(
                 zone=zone,
                 server=ns3,
                 defaults={
                     'config_dirty': True,
                     'config_dirty_since': now()
                 }
             )
         
Sync process:
         │
         └─► For each dirty ZoneServerStatus:
             ├─► Update server configuration
             ├─► Reload server
             └─► Success: status.config_dirty = False
                         status.config_dirty_since = None
                         status.last_sync_time = now()
```

### 4. Partial Sync Failure

When synchronization fails for some servers:

```
Initial state:
- Zone content_dirty = True
- ZoneServerStatus(zone, ns2).config_dirty = True
- ZoneServerStatus(zone, ns3).config_dirty = True

Sync attempt:
         │
         ├─► Master sync: SUCCESS
         │   └─► Zone.content_dirty = False
         │
         ├─► ns2 config sync: SUCCESS
         │   └─► ZoneServerStatus(zone, ns2).config_dirty = False
         │        ZoneServerStatus(zone, ns2).last_sync_time = now()
         │
         └─► ns3 config sync: FAILED
             └─► ZoneServerStatus(zone, ns3).config_dirty = True (remains)
                  ZoneServerStatus(zone, ns3).last_sync_time = None (unchanged)

Result:
- Zone is partially synchronized
- Next sync will only attempt ns3
```

## SlaveOnlyZone Tracking

For SlaveOnlyZone objects, all status tracking is done through SlaveOnlyZoneServerStatus:

```
┌─────────────────────────────────────────────────────────────────┐
│                         SlaveOnlyZone                           │
│  - origin: str                                                  │
│  - external_master: str                                         │
│  (no dirty flags at zone level)                                │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  │
                                  ▼
                        ┌───────────────────┐
                        │   Slave Servers   │
                        │  ns2.example.com  │
                        │  ns3.example.com  │
                        └───────────────────┘
                                  │
                                  ▼
                 ┌─────────────────────────────────────┐
                 │   SlaveOnlyZoneServerStatus         │
                 │  - zone: SlaveOnlyZone              │
                 │  - server: Server                   │
                 │  - config_dirty: bool               │
                 │  - config_dirty_since: datetime     │
                 │  - last_sync_time: datetime         │
                 └─────────────────────────────────────┘
```

## Database Queries

### Find all zones needing sync:

```sql
-- Zones with content or master config changes
SELECT * FROM manager_zone 
WHERE content_dirty = true 
   OR master_config_dirty = true;

-- Zones with slave servers needing config update
SELECT DISTINCT z.* FROM manager_zone z
JOIN manager_zoneserverstatus zss ON z.id = zss.zone_id
WHERE zss.config_dirty = true;

-- Slave-only zones needing sync
SELECT DISTINCT z.* FROM manager_slaveonlyzone z
JOIN manager_slaveonlyzoneserverstatus szss ON z.id = szss.zone_id
WHERE szss.config_dirty = true;
```

### Find servers needing reload:

```sql
-- All servers with pending zone config changes
SELECT DISTINCT s.* FROM manager_server s
LEFT JOIN manager_zoneserverstatus zss ON s.id = zss.server_id
LEFT JOIN manager_slaveonlyzoneserverstatus szss ON s.id = szss.server_id
WHERE zss.config_dirty = true 
   OR szss.config_dirty = true;
```

## Benefits

1. **Accurate Tracking**: Each server's sync state is independent
2. **Efficient Retries**: Only failed servers are retried
3. **Partial Success**: Some servers can be up-to-date while others are pending
4. **Clear History**: Timestamps show exactly when each server was last synced
5. **Scalability**: Adding/removing servers doesn't affect existing sync states

## Implementation Notes

- Status records are created automatically when zones are assigned to servers
- Dirty flags are only cleared after successful sync
- `last_sync_time` is only updated on success (remains NULL or unchanged on failure)
- The system handles both push (content to master) and config reload scenarios
- M2M signals ensure status records are created when server assignments change