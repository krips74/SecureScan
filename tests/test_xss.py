#!/usr/bin/env python3
"""
Example test file demonstrating XSS scanner usage
Run this after starting the Flask server
"""

import os
import json
import time

import pytest
import requests

# Configuration
API_BASE_URL = "http://localhost:5001/api/xss"

TIMEOUT_SECONDS = 15

# These are integration tests (they require a running backend and may hit external targets).
# Skip by default to keep local unit test runs deterministic.
INTEGRATION_ENABLED = os.getenv("SECURESCAN_INTEGRATION") == "1"
pytestmark = pytest.mark.skipif(
    not INTEGRATION_ENABLED,
    reason="Integration tests disabled. Set SECURESCAN_INTEGRATION=1 and start the server to run these.",
)

# Test URLs (intentionally vulnerable sites for testing)
TEST_URLS = [
    "http://testphp.vulnweb.com/search.php?test=query",
    "http://testphp.vulnweb.com/listproducts.php?cat=1",
]


def test_health_check():
    """Test if the XSS scanner is healthy"""
    print("\n" + "="*50)
    print("Testing Health Check...")
    print("="*50)
    
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=TIMEOUT_SECONDS)
        data = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(data, indent=2)}")
        
        if data.get("available"):
            print("✅ Scanner is healthy and ready")
            return True
        else:
            print("❌ Scanner is not available")
            return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_single_scan(url):
    """Test scanning a single URL"""
    print("\n" + "="*50)
    print(f"Testing Single URL Scan: {url}")
    print("="*50)
    
    try:
        payload = {
            "url": url
        }
        
        print(f"Sending request...")
        start_time = time.time()
        
        response = requests.post(
            f"{API_BASE_URL}/scan",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
        
        elapsed_time = time.time() - start_time
        data = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"Scan Time: {elapsed_time:.2f} seconds")
        
        if data.get("success"):
            scan_data = data.get("data", {})
            total_vulns = scan_data.get("total_found", 0)
            
            print(f"✅ Scan completed successfully")
            print(f"Total Vulnerabilities Found: {total_vulns}")
            
            if total_vulns > 0:
                print("\nVulnerabilities:")
                for i, vuln in enumerate(scan_data.get("vulnerabilities", []), 1):
                    print(f"\n  {i}. {vuln.get('type')} - {vuln.get('severity')}")
                    print(f"     Parameter: {vuln.get('parameter')}")
                    print(f"     Payload: {vuln.get('payload')}")
            else:
                print("No vulnerabilities detected")
            
            return True
        else:
            print(f"❌ Scan failed: {data.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_batch_scan(urls):
    """Test scanning multiple URLs"""
    print("\n" + "="*50)
    print(f"Testing Batch Scan: {len(urls)} URLs")
    print("="*50)
    
    try:
        payload = {
            "urls": urls
        }
        
        print(f"Sending request...")
        start_time = time.time()
        
        response = requests.post(
            f"{API_BASE_URL}/scan/batch",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
        
        elapsed_time = time.time() - start_time
        data = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"Total Time: {elapsed_time:.2f} seconds")
        
        if data.get("success"):
            batch_data = data.get("data", {})
            total_scanned = batch_data.get("total_scanned", 0)
            total_vulns = batch_data.get("total_vulnerabilities", 0)
            
            print(f"✅ Batch scan completed")
            print(f"URLs Scanned: {total_scanned}")
            print(f"Total Vulnerabilities: {total_vulns}")
            
            # Show per-URL results
            for scan in batch_data.get("scans", []):
                target = scan.get("target", "unknown")
                found = scan.get("total_found", 0)
                success = scan.get("success", False)
                
                status = "✅" if success else "❌"
                print(f"\n  {status} {target}: {found} vulnerabilities")
            
            return True
        else:
            print(f"❌ Batch scan failed: {data.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_custom_parameters():
    """Test scanning with custom parameters"""
    print("\n" + "="*50)
    print("Testing Custom Parameters")
    print("="*50)
    
    url = "http://testphp.vulnweb.com/search.php?test=query&searchFor=test"
    
    try:
        payload = {
            "url": url,
            "parameters": ["test", "searchFor"]
        }
        
        print(f"URL: {url}")
        print(f"Custom Parameters: {payload['parameters']}")
        print(f"Sending request...")
        
        response = requests.post(
            f"{API_BASE_URL}/scan",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=TIMEOUT_SECONDS,
        )
        
        data = response.json()
        
        if data.get("success"):
            print(f"✅ Scan with custom parameters completed")
            scan_data = data.get("data", {})
            print(f"Vulnerabilities Found: {scan_data.get('total_found', 0)}")
            return True
        else:
            print(f"❌ Scan failed: {data.get('error')}")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_invalid_input():
    """Test error handling with invalid input"""
    print("\n" + "="*50)
    print("Testing Error Handling")
    print("="*50)
    
    test_cases = [
        {"name": "Missing URL", "payload": {}},
        {"name": "Invalid URL", "payload": {"url": "not-a-url"}},
        {"name": "Wrong protocol", "payload": {"url": "ftp://example.com"}},
    ]
    
    for test in test_cases:
        print(f"\n  Testing: {test['name']}")
        try:
            response = requests.post(
                f"{API_BASE_URL}/scan",
                json=test["payload"],
                headers={"Content-Type": "application/json"},
                timeout=TIMEOUT_SECONDS,
            )
            
            data = response.json()
            
            if not data.get("success"):
                print(f"  ✅ Correctly rejected: {data.get('error')}")
            else:
                print(f"  ❌ Should have been rejected")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")


def main():
    """Run all tests"""
    print("""
    ╔══════════════════════════════════════════╗
    ║    SecureScan XSS Scanner - Test Suite      ║
    ╚══════════════════════════════════════════╝
    
    This script tests the XSS scanner API
    Make sure the Flask server is running!
    """)
    
    # Check if server is running
    try:
        requests.get("http://localhost:5001/health", timeout=2)
    except:
        print("❌ Cannot connect to Flask server")
        print("Please start the server with: python run.py")
        return
    
    results = []
    
    # Run tests
    results.append(("Health Check", test_health_check()))
    
    if results[0][1]:  # Only continue if health check passed
        results.append(("Single URL Scan", test_single_scan(TEST_URLS[0])))
        results.append(("Batch Scan", test_batch_scan(TEST_URLS)))
        results.append(("Custom Parameters", test_custom_parameters()))
        test_invalid_input()  # This doesn't return a result
    
    # Summary
    print("\n" + "="*50)
    print("TEST SUMMARY")
    print("="*50)
    
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name:.<40} {status}")
    
    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)
    
    print("="*50)
    print(f"Results: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n🎉 All tests passed!")
    else:
        print("\n⚠️  Some tests failed")


if __name__ == '__main__':
    main()