#!/usr/bin/env python3

import os
os.environ['DISABLE_CLI_PARSING'] = '1'

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import asyncio
import pytest
from teleddns_server.view import trigger_background_sync, _sync_event


class TestEventSync:
    """Test the event-driven sync functionality"""

    @pytest.mark.asyncio
    async def test_trigger_background_sync_sets_event(self):
        """Test that trigger_background_sync() sets the event"""
        # Import and set up the sync event for testing
        import teleddns_server.view as view
        view._sync_event = asyncio.Event()

        # Clear any existing event state
        view._sync_event.clear()
        assert not view._sync_event.is_set()

        # Trigger the sync
        trigger_background_sync()

        # Verify event is set
        assert view._sync_event.is_set()

        # Clean up
        view._sync_event.clear()

    @pytest.mark.asyncio
    async def test_sync_event_wait_for_trigger(self):
        """Test that we can wait for the sync event trigger"""
        # Import and set up the sync event for testing
        import teleddns_server.view as view
        view._sync_event = asyncio.Event()

        # Clear any existing event state
        view._sync_event.clear()

        # Start a task that will trigger the event after a short delay
        async def delayed_trigger():
            await asyncio.sleep(0.1)
            trigger_background_sync()

        trigger_task = asyncio.create_task(delayed_trigger())

        # Wait for the event with a reasonable timeout
        try:
            await asyncio.wait_for(view._sync_event.wait(), timeout=1.0)
            # If we get here, the event was set successfully
            assert view._sync_event.is_set()
        except asyncio.TimeoutError:
            pytest.fail("Event was not triggered within timeout")
        finally:
            # Clean up
            await trigger_task
            view._sync_event.clear()

    @pytest.mark.asyncio
    async def test_sync_event_timeout_behavior(self):
        """Test timeout behavior when event is not triggered"""
        # Import and set up the sync event for testing
        import teleddns_server.view as view
        view._sync_event = asyncio.Event()

        # Clear any existing event state
        view._sync_event.clear()

        # Try to wait for event with short timeout (should timeout)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(view._sync_event.wait(), timeout=0.1)

        # Event should still not be set
        assert not view._sync_event.is_set()

    def test_trigger_background_sync_no_event_set(self):
        """Test that trigger_background_sync handles missing event gracefully"""
        # Import and clear the sync event
        import teleddns_server.view as view
        view._sync_event = None
        
        # This should not raise an exception even without an event
        trigger_background_sync()
        # Test passes if no exception is raised
