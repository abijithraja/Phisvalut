#!/usr/bin/env python3
"""
Test script for the new ultra feature extractor
"""

import sys
import logging
from main import PhishVaultMLDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_feature_extractor():
    """Test the new ultra feature extractor"""
    print("🧪 Testing Ultra Feature Extractor")
    print("=" * 50)
    
    # Initialize detector
    try:
        detector = PhishVaultMLDetector()
        print("✅ Detector initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize detector: {e}")
        return False
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "https://github.com/user/repo",
        "http://suspicious-phishing-site.tk/login?verify=account",
        "https://192.168.1.1:8080/admin",
        "https://paypal-security-update.example.com/signin"
    ]
    
    for url in test_urls:
        print(f"\n🔗 Testing URL: {url}")
        print("-" * 40)
        
        try:
            # Test quick extraction (no deep analysis)
            print("📈 Quick extraction (deep=False):")
            features_quick = detector.extract_url_features(url, deep=False)
            print(f"   Features extracted: {len(features_quick)}")
            
            # Show some key features
            key_features = ['length_url', 'https_enabled', 'ip', 'nb_subdomains', 'phish_hints', 'suspicious_tld']
            for feat in key_features:
                if feat in features_quick:
                    print(f"   {feat}: {features_quick[feat]}")
            
            # Test deep extraction (with HTML/TLS analysis)
            print("\n🔍 Deep extraction (deep=True):")
            features_deep = detector.extract_url_features(url, deep=True, fetch_timeout=3.0, tls_timeout=1.0)
            print(f"   Features extracted: {len(features_deep)}")
            
            # Show additional deep features
            deep_features = ['nb_hyperlinks', 'login_form', 'external_favicon', 'certificate_present', 'domain_age']
            for feat in deep_features:
                if feat in features_deep:
                    print(f"   {feat}: {features_deep[feat]}")
            
            # Compare feature counts
            print(f"\n📊 Comparison:")
            print(f"   Quick features: {len(features_quick)}")
            print(f"   Deep features: {len(features_deep)}")
            
        except Exception as e:
            print(f"❌ Error testing {url}: {e}")
            logger.exception(f"Error testing {url}")
    
    print("\n" + "=" * 50)
    print("🎉 Ultra Feature Extractor test completed!")
    return True

def test_prediction():
    """Test prediction with new feature extractor"""
    print("\n🎯 Testing Prediction with New Features")
    print("=" * 50)
    
    try:
        detector = PhishVaultMLDetector()
        
        test_urls = [
            "https://www.google.com",
            "http://phishing-example.tk/secure-login"
        ]
        
        for url in test_urls:
            print(f"\n🔗 Predicting: {url}")
            try:
                # Test with quick scan
                result_quick = detector.predict_with_shap(url, scan_type="quick")
                print(f"   Quick scan - Phishing: {result_quick.is_phishing}, Probability: {result_quick.probability:.4f}")
                
                # Test with deep scan
                result_deep = detector.predict_with_shap(url, scan_type="deep")
                print(f"   Deep scan - Phishing: {result_deep.is_phishing}, Probability: {result_deep.probability:.4f}")
                
            except Exception as e:
                print(f"   ❌ Prediction failed: {e}")
                logger.exception(f"Prediction failed for {url}")
        
    except Exception as e:
        print(f"❌ Failed to test prediction: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🌟 PhishVault Ultra Feature Extractor Test Suite")
    print("=" * 60)
    
    success = True
    
    # Test feature extraction
    if not test_feature_extractor():
        success = False
    
    # Test prediction
    if not test_prediction():
        success = False
    
    if success:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)
