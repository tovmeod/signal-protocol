"""Test deterministic signature generation with fixed_random parameter."""

import pytest
from signal_protocol.curve import KeyPair, PrivateKey


def test_keypair_deterministic_signature():
    """Test that KeyPair.calculate_signature produces deterministic results with fixed_random."""
    key_pair = KeyPair.generate()
    message = b"test message for signing"
    fixed_random = b'\x99' * 64
    
    # Generate multiple signatures with same fixed random
    sig1 = key_pair.calculate_signature(message, fixed_random=fixed_random)
    sig2 = key_pair.calculate_signature(message, fixed_random=fixed_random)
    sig3 = key_pair.calculate_signature(message, fixed_random=fixed_random)
    
    # All signatures should be identical when using fixed random
    assert sig1 == sig2 == sig3, "Signatures should be deterministic with fixed random"
    
    # Verify the signature is valid
    public_key = key_pair.public_key()
    assert public_key.verify_signature(message, sig1), "Signature should be valid"


def test_keypair_random_signature_differs():
    """Test that KeyPair.calculate_signature produces different results without fixed_random."""
    key_pair = KeyPair.generate()
    message = b"test message for signing"
    
    # Generate multiple signatures without fixed random (should be different)
    sig1 = key_pair.calculate_signature(message)
    sig2 = key_pair.calculate_signature(message)
    sig3 = key_pair.calculate_signature(message)
    
    # Signatures should be different when using random generator
    signatures = [sig1, sig2, sig3]
    unique_signatures = set(signatures)
    assert len(unique_signatures) == 3, "Random signatures should all be different"
    
    # All signatures should still be valid
    public_key = key_pair.public_key()
    for sig in signatures:
        assert public_key.verify_signature(message, sig), "All signatures should be valid"


def test_privatekey_deterministic_signature():
    """Test that PrivateKey.calculate_signature produces deterministic results with fixed_random."""
    key_pair = KeyPair.generate()
    private_key = key_pair.private_key()
    message = b"test message for signing"
    fixed_random = b'\xaa' * 32
    
    # Generate multiple signatures with same fixed random
    sig1 = private_key.calculate_signature(message, fixed_random=fixed_random)
    sig2 = private_key.calculate_signature(message, fixed_random=fixed_random)
    sig3 = private_key.calculate_signature(message, fixed_random=fixed_random)
    
    # All signatures should be identical when using fixed random
    assert sig1 == sig2 == sig3, "Signatures should be deterministic with fixed random"
    
    # Verify the signature is valid
    public_key = key_pair.public_key()
    assert public_key.verify_signature(message, sig1), "Signature should be valid"


def test_privatekey_random_signature_differs():
    """Test that PrivateKey.calculate_signature produces different results without fixed_random."""
    key_pair = KeyPair.generate()
    private_key = key_pair.private_key()
    message = b"test message for signing"
    
    # Generate multiple signatures without fixed random (should be different)
    sig1 = private_key.calculate_signature(message)
    sig2 = private_key.calculate_signature(message)
    sig3 = private_key.calculate_signature(message)
    
    # Signatures should be different when using random generator
    signatures = [sig1, sig2, sig3]
    unique_signatures = set(signatures)
    assert len(unique_signatures) == 3, "Random signatures should all be different"
    
    # All signatures should still be valid
    public_key = key_pair.public_key()
    for sig in signatures:
        assert public_key.verify_signature(message, sig), "All signatures should be valid"


def test_different_fixed_random_produces_different_signatures():
    """Test that different fixed_random values produce different signatures."""
    key_pair = KeyPair.generate()
    message = b"test message for signing"
    
    fixed_random1 = b'\x11' * 32
    fixed_random2 = b'\x22' * 32
    fixed_random3 = b'\x33' * 32
    
    sig1 = key_pair.calculate_signature(message, fixed_random=fixed_random1)
    sig2 = key_pair.calculate_signature(message, fixed_random=fixed_random2)
    sig3 = key_pair.calculate_signature(message, fixed_random=fixed_random3)
    
    # Different fixed random should produce different signatures
    signatures = [sig1, sig2, sig3]
    unique_signatures = set(signatures)
    assert len(unique_signatures) == 3, "Different fixed random should produce different signatures"
    
    # All signatures should be valid
    public_key = key_pair.public_key()
    for sig in signatures:
        assert public_key.verify_signature(message, sig), "All signatures should be valid"


def test_fixed_random_seed_truncation():
    """Test that fixed_random handles different seed lengths correctly."""
    key_pair = KeyPair.generate()
    message = b"test message for signing"
    
    # Test with short seed (should be padded with zeros)
    short_seed = b'\xdd\xdd'
    sig1 = key_pair.calculate_signature(message, fixed_random=short_seed)
    sig2 = key_pair.calculate_signature(message, fixed_random=short_seed)
    assert sig1 == sig2, "Short seed should produce deterministic results"
    
    # Test with long seed (should be truncated to 32 bytes)
    long_seed = b'\xee' * 100
    sig3 = key_pair.calculate_signature(message, fixed_random=long_seed)
    sig4 = key_pair.calculate_signature(message, fixed_random=long_seed)
    assert sig3 == sig4, "Long seed should produce deterministic results"
    
    # Test that truncated long seed produces same result as first 32 bytes
    truncated_seed = long_seed[:32]
    sig5 = key_pair.calculate_signature(message, fixed_random=truncated_seed)
    assert sig3 == sig5, "Truncated seed should match explicit 32-byte seed"


def test_backward_compatibility():
    """Test that existing code without fixed_random parameter still works."""
    key_pair = KeyPair.generate()
    private_key = key_pair.private_key()
    message = b"test message for signing"
    
    # These should work without any changes to existing code
    sig1 = key_pair.calculate_signature(message)
    sig2 = private_key.calculate_signature(message)
    
    # Verify signatures are valid
    public_key = key_pair.public_key()
    assert public_key.verify_signature(message, sig1), "KeyPair signature should be valid"
    assert public_key.verify_signature(message, sig2), "PrivateKey signature should be valid"


def test_none_fixed_random_same_as_no_parameter():
    """Test that fixed_random=None behaves the same as not providing the parameter."""
    key_pair = KeyPair.generate()
    message = b"test message for signing"
    
    # These should both use random generation
    sig1 = key_pair.calculate_signature(message)
    sig2 = key_pair.calculate_signature(message, fixed_random=None)
    
    # Both should be valid (though likely different due to randomness)
    public_key = key_pair.public_key()
    assert public_key.verify_signature(message, sig1), "No parameter signature should be valid"
    assert public_key.verify_signature(message, sig2), "None parameter signature should be valid"