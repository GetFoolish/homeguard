"""Test TOTP authentication system."""

import pytest
from src.myproxy.auth.totp import TOTPManager, AccessDuration


class TestTOTPManager:
    """Test TOTP manager functionality."""
    
    def test_totp_manager_initialization(self):
        """Test TOTP manager initializes correctly."""
        manager = TOTPManager()
        
        # Check that all duration types have generators
        expected_durations = ["15min", "30min", "1hr", "2hr", "4hr", "24hr", "1week", "forever"]
        for duration in expected_durations:
            assert duration in manager._totp_generators
    
    def test_generate_current_codes(self):
        """Test current TOTP code generation."""
        manager = TOTPManager()
        codes = manager.generate_current_codes()
        
        # Should have codes for all durations
        assert len(codes) == 8
        
        # All codes should be 6 digits
        for code in codes.values():
            assert len(code) == 6
            assert code.isdigit()
    
    def test_validate_code(self):
        """Test TOTP code validation."""
        manager = TOTPManager()
        
        # Generate a current code and validate it
        codes = manager.generate_current_codes()
        test_duration = "15min"
        test_code = codes[test_duration]
        
        result = manager.validate_code(test_code)
        assert result is not None
        duration_key, duration_seconds = result
        assert duration_key == test_duration
        assert duration_seconds == 900  # 15 minutes in seconds
    
    def test_invalid_code_validation(self):
        """Test validation of invalid TOTP codes."""
        manager = TOTPManager()
        
        # Test invalid code
        result = manager.validate_code("000000")
        assert result is None
        
        # Test non-numeric code
        result = manager.validate_code("abc123")
        assert result is None
    
    def test_get_expiry_time(self):
        """Test expiry time calculation."""
        manager = TOTPManager()
        
        # Test normal duration
        expiry = manager.get_expiry_time(3600)  # 1 hour
        assert expiry is not None
        
        # Test forever duration
        expiry = manager.get_expiry_time(-1)
        assert expiry is None
    
    def test_get_provisioning_uris(self):
        """Test provisioning URI generation for QR codes."""
        manager = TOTPManager()
        uris = manager.get_provisioning_uris()
        
        assert len(uris) == 8
        for duration, uri in uris.items():
            assert uri.startswith("otpauth://totp/")
            assert "MyProxy" in uri
            assert duration in uri


if __name__ == "__main__":
    pytest.main([__file__, "-v"])