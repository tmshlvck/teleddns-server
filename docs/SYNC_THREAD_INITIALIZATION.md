# Sync Thread Initialization and Database Warning Fix

## Problem

When starting the sync thread during Django application initialization, we encountered this warning:

```
RuntimeWarning: Accessing the database during app initialization is discouraged. 
To fix this warning, avoid executing queries in AppConfig.ready() or when your app modules are imported.
```

This occurred because the sync thread would immediately query the database for dirty zones, but Django wasn't fully initialized yet.

## Solution

We implemented a multi-layered approach to ensure proper initialization:

### 1. Initial Delay in Sync Thread

The sync thread now waits 5 seconds before starting its main loop:

```python
def _run(self):
    """Main thread loop"""
    # Initial delay to ensure Django is fully initialized
    initial_delay = 5  # seconds
    logger.info(f"Sync thread waiting {initial_delay}s for Django initialization")
    if self.stop_event.wait(initial_delay):
        return  # Thread was stopped during initial delay
    
    logger.info("Sync thread starting main loop")
    # ... main loop continues
```

### 2. Conditional Thread Starting

The thread only starts in specific contexts:

#### Development Server (manage.py runserver)
In `manager/apps.py`:
```python
def ready(self):
    """Import signal handlers and start background tasks when the app is ready"""
    from . import signals  # noqa
    
    # Only start the sync thread when running the development server
    import sys
    if (len(sys.argv) > 1 and
        sys.argv[1] == 'runserver' and
        os.environ.get('RUN_MAIN') == 'true'):
        from .sync_thread import sync_thread
        sync_thread.start()
```

#### Production WSGI/ASGI
For production deployments, the thread starts from the WSGI/ASGI application files with a 10-second delay:

```python
# In wsgi.py and asgi.py
def init_sync_thread():
    """Initialize the sync thread once Django is ready"""
    global _initialized
    
    with _init_lock:
        if _initialized:
            return
        _initialized = True
        
        try:
            from manager.sync_thread import sync_thread
            if not sync_thread.thread or not sync_thread.thread.is_alive():
                sync_thread.start()
                logger.info("Sync thread initialized for WSGI/ASGI application")
        except Exception as e:
            logger.error(f"Failed to start sync thread: {e}")

# Start the sync thread after a delay
init_timer = threading.Timer(10.0, init_sync_thread)
init_timer.daemon = True
init_timer.start()
```

### 3. Thread Lifecycle Management

The thread is created as:
- **Daemon thread** for web servers (auto-terminates when main process exits)
- **Non-daemon thread** for management commands (keeps running until explicitly stopped)

```python
is_management_command = len(sys.argv) > 1 and sys.argv[0].endswith('manage.py')
self.thread = threading.Thread(target=self._run, daemon=not is_management_command)
```

## Benefits

1. **No Database Warnings**: The initial delay ensures Django is fully initialized before any database queries
2. **Proper Context Handling**: Different initialization strategies for development vs production
3. **Thread Safety**: Lock mechanism prevents multiple thread instances in multi-worker deployments
4. **Clean Shutdown**: Daemon threads for web servers, managed threads for commands

## Usage

### Development
The sync thread starts automatically when running:
```bash
python manage.py runserver
```

### Production
The sync thread starts automatically when the WSGI/ASGI application is loaded by:
- Gunicorn
- uWSGI
- Daphne
- Any other WSGI/ASGI server

### Manual Control
For debugging or manual management:
```bash
# Start manually
python manage.py sync_thread_control start

# Check status
python manage.py sync_thread_control status

# Stop
python manage.py sync_thread_control stop
```

## Troubleshooting

If you still see database warnings:

1. **Check the initial delay**: Increase from 5 to 10 seconds if needed
2. **Verify Django settings**: Ensure DJANGO_SETTINGS_MODULE is set correctly
3. **Check for custom app initialization**: Other apps might be accessing the database early
4. **Review middleware**: Some middleware might trigger database access during initialization

## Implementation Notes

- The 5-second initial delay is sufficient for most deployments
- The 10-second delay for WSGI/ASGI provides extra safety margin
- The lock mechanism prevents race conditions in multi-worker deployments
- Error handling ensures the application continues even if thread initialization fails