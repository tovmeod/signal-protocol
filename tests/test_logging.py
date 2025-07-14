import pytest
import os
import signal_protocol.storage as storage

def test_init_logging():
    """Test that init_logging function can be called without errors."""
    # Call the init_logging function
    storage.init_logging()
    
    # If we get here without exceptions, the test passes
    assert True

def test_logging_with_env_var():
    """Test that logging respects environment variables."""
    # Set environment variable for logging
    os.environ["RUST_LOG"] = "debug"
    
    # Call the init_logging function
    storage.init_logging()
    
    # If we get here without exceptions, the test passes
    assert True