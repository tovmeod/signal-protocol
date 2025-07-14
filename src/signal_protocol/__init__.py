import sys
import asyncio
import threading
import inspect
from typing import Optional, Any, Coroutine, TypeVar
import concurrent.futures
import functools

# Import the compiled Rust extension module directly
from . import _signal_protocol

# Re-export all submodules and make them available in sys.modules
# so that "from signal_protocol.submodule import Foo" works.
_submodules = {
    "address": _signal_protocol.address,
    "curve": _signal_protocol.curve,
    "error": _signal_protocol.error,
    "fingerprint": _signal_protocol.fingerprint,
    "group_cipher": _signal_protocol.group_cipher,
    "identity_key": _signal_protocol.identity_key,
    "protocol": _signal_protocol.protocol,
    "ratchet": _signal_protocol.ratchet,
    "sealed_sender": _signal_protocol.sealed_sender,
    "sender_keys": _signal_protocol.sender_keys,
    "session_cipher": _signal_protocol.session_cipher,
    "session": _signal_protocol.session,
    "state": _signal_protocol.state,
    "storage": _signal_protocol.storage,
}

for name, module in _submodules.items():
    globals()[name] = module
    sys.modules[f"signal_protocol.{name}"] = module


class PersistentStorageBase(_signal_protocol.storage.PersistentStorageProtocol):
    """Enhanced base class with async executor pattern for storage implementations.
    
    This class provides automatic async/sync detection and execution for storage methods.
    If you implement async methods, they will be executed in a persistent event loop.
    If you implement sync methods, they will be called directly without any async overhead.
    """
    
    def __init__(self):
        super().__init__()
        self._async_executor = None
        self._executor_thread = None
        self._loop = None
        self._shutdown_event = None
    
    def _call_method(self, method_name: str, *args, **kwargs):
        """Call a method, handling async execution if needed."""
        # Get the method from the final subclass - this will get the child's implementation
        method = getattr(self, method_name)
        
        # Check if it's an async method
        if inspect.iscoroutinefunction(method):
            # Ensure async executor is running
            self._ensure_async_executor()
            # Call the async method
            return self._call_async(method(*args, **kwargs))
        else:
            # Call sync method directly
            return method(*args, **kwargs)
    
    def _ensure_async_executor(self):
        """Ensure the async executor is running if we have async methods."""
        if self._async_executor is not None and self._async_executor.is_set():
            return  # Already running
        
        # Create the async executor
        self._shutdown_event = threading.Event()
        self._async_executor = threading.Event()
        
        def run_event_loop():
            """Run the asyncio event loop in a separate thread."""
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            self._async_executor.set()  # Signal that loop is ready
            
            # Run until shutdown
            self._loop.run_until_complete(self._wait_for_shutdown())
            self._loop.close()
        
        self._executor_thread = threading.Thread(target=run_event_loop, daemon=True)
        self._executor_thread.start()
        
        # Wait for the loop to be ready
        self._async_executor.wait()
    
    async def _wait_for_shutdown(self):
        """Wait for shutdown signal."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(0.1)
    
    def _call_async(self, coro):
        """Execute a coroutine in the async executor and return the result."""
        future = concurrent.futures.Future()
        
        def set_result_callback(task):
            if task.exception():
                future.set_exception(task.exception())
            else:
                future.set_result(task.result())
        
        # Schedule the coroutine using call_soon_threadsafe without asyncio.create_task
        self._loop.call_soon_threadsafe(lambda: asyncio.ensure_future(coro, loop=self._loop).add_done_callback(set_result_callback))
        
        # Wait for result
        return future.result()
    
    # Interface methods - subclasses should implement these methods
    # These can be either sync or async - the base class handles both automatically
    # Rust code calls _call_method('method_name', *args) instead of calling these directly
    
    def save_identity(self, address, identity_key):
        """Save identity for the given address. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement save_identity")
    
    def get_identity(self, address):
        """Get identity for the given address. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement get_identity")
    
    def store_session(self, address, session_record):
        """Store session for the given address. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement store_session")
    
    def load_session(self, address):
        """Load session for the given address. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement load_session")
    
    def contains_session(self, address):
        """Check if session exists for the given address. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement contains_session")
    
    def get_pre_key(self, pre_key_id):
        """Get prekey by ID. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement get_pre_key")
    
    def save_pre_key(self, pre_key_id, pre_key_record):
        """Save prekey record. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement save_pre_key")
    
    def remove_pre_key(self, pre_key_id):
        """Remove prekey by ID. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement remove_pre_key")
    
    def get_signed_pre_key(self, signed_pre_key_id):
        """Get signed prekey by ID. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement get_signed_pre_key")
    
    def save_signed_pre_key(self, signed_pre_key_id, signed_pre_key_record):
        """Save signed prekey record. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement save_signed_pre_key")
    
    def store_sender_key(self, sender_key_name, sender_key_record):
        """Store sender key record. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement store_sender_key")
    
    def load_sender_key(self, sender_key_name):
        """Load sender key by name. Implement in subclass."""
        raise NotImplementedError("Subclasses must implement load_sender_key")
    
    def close(self):
        """Clean up the async executor."""
        if self._shutdown_event:
            self._shutdown_event.set()
        
        if self._executor_thread and self._executor_thread.is_alive():
            self._executor_thread.join(timeout=1.0)
        
        # Call any custom close implementation
        if hasattr(super(), 'close'):
            super().close()


# Export everything
__all__ = [
    'address',
    'curve',
    'error',
    'fingerprint',
    'group_cipher',
    'identity_key',
    'protocol',
    'ratchet',
    'sealed_sender',
    'sender_keys',
    'session_cipher',
    'session',
    'state',
    'storage',
    'PersistentStorageBase',
]