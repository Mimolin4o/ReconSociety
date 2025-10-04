#!/usr/bin/env python3
"""
ReconSociety Test Script
Quick verification that all modules load correctly
"""

import sys
import importlib.util

def test_recon_society():
    """Test if ReconSociety can be imported and basic functions work"""
    print("🔍 Testing ReconSociety Framework...")

    try:
        # Test importing the main module
        spec = importlib.util.spec_from_file_location("recon_society", "recon_society.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        print("✅ ReconSociety module loaded successfully")

        # Test banner
        module.Banner.show()
        print("✅ Banner display working")

        # Test ReconSociety class initialization
        recon = module.ReconSociety()
        print("✅ ReconSociety class initialized")

        # Test logging
        recon.log("Test message", "INFO")
        print("✅ Logging system working")

        print("\n🎉 All tests passed! ReconSociety is ready to use.")
        return True

    except Exception as e:
        print(f"❌ Error testing ReconSociety: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_recon_society()
    sys.exit(0 if success else 1)
