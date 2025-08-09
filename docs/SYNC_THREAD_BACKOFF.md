# Sync Thread Backoff Behavior

## Overview

The TeleDDNS sync thread implements an exponential backoff strategy with a maximum cap to handle failed synchronization attempts. This ensures the system continues retrying indefinitely while avoiding overwhelming failed servers.

## Configuration Parameters

- **SYNC_THREAD_INTERVAL**: Base check interval (default: 60 seconds)
- **SYNC_THREAD_BACKOFF_BASE**: Exponential base (default: 2)
- **SYNC_THREAD_MAX_BACKOFF_SECONDS**: Maximum backoff time (default: 86400 seconds = 24 hours)

## Backoff Calculation

The backoff time is calculated as:
```
backoff_time = min(BACKOFF_BASE ^ failure_count, MAX_BACKOFF_SECONDS)
```

## Example Backoff Progression

With default settings (base=2, max=86400):

| Failure Count | Backoff Time | Human Readable |
|--------------|--------------|----------------|
| 1 | 2 seconds | 2 seconds |
| 2 | 4 seconds | 4 seconds |
| 3 | 8 seconds | 8 seconds |
| 4 | 16 seconds | 16 seconds |
| 5 | 32 seconds | 32 seconds |
| 6 | 64 seconds | 1.1 minutes |
| 7 | 128 seconds | 2.1 minutes |
| 8 | 256 seconds | 4.3 minutes |
| 9 | 512 seconds | 8.5 minutes |
| 10 | 1,024 seconds | 17.1 minutes |
| 11 | 2,048 seconds | 34.1 minutes |
| 12 | 4,096 seconds | 1.1 hours |
| 13 | 8,192 seconds | 2.3 hours |
| 14 | 16,384 seconds | 4.6 hours |
| 15 | 32,768 seconds | 9.1 hours |
| 16 | 65,536 seconds | 18.2 hours |
| 17+ | 86,400 seconds | 24 hours (capped) |

## Key Behaviors

### 1. Continuous Retrying
- The system never gives up on synchronization
- Failed items continue to be retried at the maximum backoff interval
- This ensures eventual consistency when servers come back online

### 2. Per-Item Tracking
- Each zone-server combination has its own failure counter
- Different items can be at different stages of backoff
- Successful sync of one item doesn't affect others

### 3. Ephemeral State
- All failure tracking is in-memory only
- Server restart clears all backoff states
- This provides a natural "reset" mechanism

### 4. Immediate Recovery
- Successful synchronization immediately clears the failure counter
- The item returns to normal check intervals
- No "penalty period" after recovery

## Example Scenario

1. **Initial Failure** (12:00:00)
   - Zone sync fails
   - Next retry in 2 seconds (12:00:02)

2. **Second Failure** (12:00:02)
   - Still failing
   - Next retry in 4 seconds (12:00:06)

3. **Multiple Failures** (over next hours)
   - Backoff increases exponentially
   - By failure #17, retries happen every 24 hours

4. **Server Comes Online** (3 days later)
   - Next scheduled retry succeeds
   - Failure counter resets to 0
   - Zone returns to normal sync interval

## Monitoring

Check current backoff states:
```bash
python manage.py sync_thread_control status
```

Force immediate retry (bypasses backoff):
```bash
python manage.py sync_thread_control force-sync
```

## Best Practices

1. **Set Reasonable Max Backoff**: 24 hours is a good default, but adjust based on your needs
2. **Monitor Failure Counts**: High failure counts indicate persistent issues
3. **Use Force Sync Sparingly**: Let the backoff mechanism work naturally
4. **Plan for Restarts**: Remember that server restarts clear backoff states

## Comparison with Previous Approach

| Aspect | Max Retries Approach | Max Backoff Approach |
|--------|---------------------|---------------------|
| Failed items | Give up after N attempts | Retry indefinitely |
| Long-term behavior | Manual intervention needed | Self-healing |
| Resource usage | Lower (stops trying) | Controlled (long intervals) |
| Recovery time | Requires manual reset | Automatic when server recovers |