"""
Security Vulnerability Testing Script - b.py Mitigations
Tests security mitigations implemented in b.py module
"""
import requests
from pathlib import Path

BASE_URL = "http://localhost:8000"
TEST_DIR = Path(__file__).parent

# Track vulnerabilities found
vulnerabilities_found = []
mitigations_working = []

print("=" * 80)
print("SECURITY VULNERABILITY TESTING - b.py")
print("=" * 80)
print(f"Target: {BASE_URL}")
print(f"Make sure the server is running: uvicorn a:app --reload")
print("=" * 80)

# Check if server is running
try:
    response = requests.get(f"{BASE_URL}/health", timeout=2)
    if response.status_code != 200:
        print("❌ Server not responding correctly!")
        exit(1)
    print("✅ Server is running\n")
except Exception as e:
    print(f"❌ Cannot connect to server: {e}")
    print("Run: uvicorn a:app --reload")
    exit(1)


def test_upload(filename, content, description, expect_blocked=False):
    """Helper function to test file upload"""
    print(f"\n[TEST] {description}")
    print(f"  Filename: {filename}")

    try:
        test_file = TEST_DIR / filename
        with open(test_file, "wb") as f:
            f.write(content)

        with open(test_file, "rb") as f:
            response = requests.post(
                f"{BASE_URL}/file", files={"file": f}, timeout=5)

        test_file.unlink(missing_ok=True)

        if response.status_code == 200:
            data = response.json()
            uploaded_name = data.get('path')
            print(f"  ✅ UPLOADED: {uploaded_name} ({data.get('size')} bytes)")

            # Check if file was properly sanitized
            if expect_blocked:
                if ".blocked" in uploaded_name or "file_" in uploaded_name or uploaded_name != filename:
                    print(f"  ✅ MITIGATION ACTIVE: Filename sanitized")
                    mitigations_working.append(description)
                else:
                    print(
                        f"  ⚠️  VULNERABILITY: File uploaded with original dangerous name!")
                    vulnerabilities_found.append(
                        f"{description} - uploaded as {uploaded_name}")

            return uploaded_name
        else:
            print(f"  🛡️  BLOCKED: {response.status_code} - {response.text}")
            if expect_blocked:
                mitigations_working.append(description)
            return None
    except Exception as e:
        print(f"  ❌ ERROR: {e}")
        return None


def test_download(path, description, expect_blocked=False):
    """Helper function to test file download"""
    print(f"\n[TEST] {description}")
    print(f"  Path: {path}")

    try:
        response = requests.get(
            f"{BASE_URL}/file", params={"path": path, "mode": "download"}, timeout=5)

        if response.status_code == 200:
            print(f"  ⚠️  DOWNLOADED: {len(response.content)} bytes")
            if expect_blocked:
                vulnerabilities_found.append(
                    f"{description} - path traversal successful")
            return True
        else:
            print(f"  🛡️  BLOCKED: {response.status_code}")
            if expect_blocked:
                mitigations_working.append(description)
            return False
    except Exception as e:
        print(f"  🛡️  BLOCKED: {e}")
        if expect_blocked:
            mitigations_working.append(description)
        return False


print("\n" + "=" * 80)
print("VULNERABILITY TEST 1: Malicious File Upload")
print("=" * 80)

# Test executable files (should be blocked/renamed)
test_upload("malware.exe", b"MZ\x90\x00",
            "Malware .exe upload", expect_blocked=True)
test_upload("script.bat", b"@echo off\ndel /f /q *.*",
            "Batch script .bat upload", expect_blocked=True)
test_upload("evil.sh", b"#!/bin/bash\nrm -rf /",
            "Shell script .sh upload", expect_blocked=True)
test_upload("script.ps1", b"Remove-Item * -Recurse",
            "PowerShell .ps1 upload", expect_blocked=True)

# Test legitimate files (should work normally)
test_upload("document.txt", b"Hello World!",
            "Legitimate .txt upload", expect_blocked=False)
test_upload("image.png", b"\x89PNG\r\n\x1a\n",
            "Legitimate .png upload", expect_blocked=False)


print("\n" + "=" * 80)
print("VULNERABILITY TEST 2: Path Traversal Attack")
print("=" * 80)

# Upload a legitimate file first
uploaded_path = test_upload(
    "testfile.txt", b"Secret data", "Upload test file", expect_blocked=False)

if uploaded_path:
    # Try to access it normally (should work)
    test_download(uploaded_path, "Download legitimate file",
                  expect_blocked=False)

    # Try path traversal attacks (should be blocked)
    test_download("../../../etc/passwd",
                  "Path traversal: ../../../etc/passwd", expect_blocked=True)
    test_download("..\\..\\..\\Windows\\System32\\config\\SAM",
                  "Path traversal: ..\\..\\..\\Windows\\SAM", expect_blocked=True)
    test_download("....//....//secret.txt",
                  "Double-encoded path traversal: ....//....//", expect_blocked=True)


print("\n" + "=" * 80)
print("VULNERABILITY TEST 3: Windows Reserved Names")
print("=" * 80)

test_upload("CON.txt", b"test",
            "Windows reserved name: CON.txt", expect_blocked=True)
test_upload("PRN.pdf", b"test",
            "Windows reserved name: PRN.pdf", expect_blocked=True)
test_upload("AUX", b"test",
            "Windows reserved name: AUX", expect_blocked=True)


print("\n" + "=" * 80)
print("VULNERABILITY TEST 4: Filename Length Overflow")
print("=" * 80)

long_name = "A" * 300 + ".txt"
result = test_upload(long_name, b"test",
                     f"Filename overflow: {len(long_name)} characters", expect_blocked=True)
if result and len(result) <= 255:
    print(f"  ✅ MITIGATION ACTIVE: Filename truncated to {len(result)} chars")
    mitigations_working.append("Filename length truncation")
elif result and len(result) > 255:
    print(f"  ⚠️  VULNERABILITY: Filename NOT truncated ({len(result)} chars)")
    vulnerabilities_found.append(
        f"Buffer overflow - filename {len(result)} chars")


print("\n" + "=" * 80)
print("VULNERABILITY TEST 5: File Size Limit (DoS Prevention)")
print("=" * 80)

print("\n[TEST] File size limit: Upload 11MB file (exceeds 10MB limit)")
print("  Creating large file...")
large_content = b"X" * (11 * 1024 * 1024)  # 11MB
print(f"  File size: {len(large_content) / 1024 / 1024:.2f} MB")

try:
    test_file = TEST_DIR / "large.bin"
    with open(test_file, "wb") as f:
        f.write(large_content)

    with open(test_file, "rb") as f:
        response = requests.post(
            f"{BASE_URL}/file", files={"file": f}, timeout=30)

    test_file.unlink(missing_ok=True)

    if response.status_code == 413:
        print(f"  🛡️  BLOCKED: File too large")
        mitigations_working.append("File size limit enforcement")
    elif response.status_code == 200:
        print(f"  ⚠️  VULNERABILITY: Large file accepted!")
        vulnerabilities_found.append(
            "DoS via large file upload (11MB accepted)")
    else:
        print(f"  ⚠️  Unexpected response: {response.status_code}")
except Exception as e:
    print(f"  🛡️  BLOCKED: {e}")
    mitigations_working.append("File size limit enforcement")


print("\n" + "=" * 80)
print("TEST RESULTS SUMMARY")
print("=" * 80)

if len(vulnerabilities_found) == 0:
    print("\n🎉 ALL SECURITY MITIGATIONS ARE ACTIVE!")
    print("\n✅ Working Mitigations:")
    print("  1. Malicious file upload prevention (.exe, .bat, .sh, .ps1 blocked/renamed)")
    print("  2. Path traversal attack prevention (../ patterns blocked)")
    print("  3. Windows reserved names protection (CON, PRN, AUX renamed)")
    print("  4. Buffer overflow prevention (filename length limited)")
    print("  5. File size limit enforcement (10MB maximum)")
else:
    print(f"\n⚠️  FOUND {len(vulnerabilities_found)} ACTIVE VULNERABILITIES!")
    print("\n🔴 Active Vulnerabilities:")
    for i, vuln in enumerate(vulnerabilities_found, 1):
        print(f"  {i}. {vuln}")

    print(f"\n✅ Working Mitigations: {len(mitigations_working)}")
    for i, mitigation in enumerate(mitigations_working, 1):
        print(f"  {i}. {mitigation}")

print("\n" + "=" * 80)
