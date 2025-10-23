"""
Test script to verify security mitigations in b.py
"""
from b import s, v, c
import sys

print("=" * 60)
print("SECURITY MITIGATION TESTS")
print("=" * 60)

# Test 1: Path Traversal in v() function
print("\n[TEST 1] Path Traversal Prevention in v()")
print("-" * 60)

test_cases_v = [
    ("../../../etc/passwd", "Path traversal Linux"),
    ("..\\..\\..\\Windows\\win.ini", "Path traversal Windows"),
    ("....//....//etc/passwd", "Double encoding bypass"),
    ("test.txt", "Path valid"),
    ("folder/test.txt", "Path valid cu subfolder"),
]

for path, desc in test_cases_v:
    try:
        result = v(path)
        print(f"✅ {desc}: '{path}' → ALLOWED: {result.name}")
    except ValueError as e:
        print(f"🛡️  {desc}: '{path}' → BLOCKED")
    except Exception as e:
        print(f"❌ {desc}: '{path}' → ERROR: {type(e).__name__}")

# Test 2: Filename Sanitization in s() function
print("\n[TEST 2] Filename Sanitization in s()")
print("-" * 60)

test_cases_s = [
    ("malware.exe", "Executable file"),
    ("script.bat", "Windows batch file"),
    ("evil.sh", "Shell script"),
    ("CON.txt", "Windows reserved name CON"),
    ("PRN.pdf", "Windows reserved name PRN"),
    ("normal_file.txt", "Normal file"),
    ("A" * 300 + ".txt", "Very long filename (300 chars)"),
    (".....hidden", "Multiple dots at start"),
    ("file with spaces.doc", "File with spaces"),
    ("../../../etc/passwd", "Path traversal in filename"),
]

for filename, desc in test_cases_s:
    result = s(filename)
    blocked = ".blocked" in result or "file_" in result or "f_" in result
    emoji = "🛡️" if blocked else "✅"
    print(f"{emoji} {desc}: '{filename[:50]}...' → '{result}'")

# Test 3: Path Cleaning in c() function
print("\n[TEST 3] Path Cleaning in c()")
print("-" * 60)

test_cases_c = [
    ("../../../etc/passwd", "Path traversal"),
    ("....//....//test", "Double encoded"),
    ("/absolute/path", "Absolute path"),
    ("normal/path/file.txt", "Normal path"),
]

for path, desc in test_cases_c:
    result = c(path)
    print(f"{'🛡️' if '../' not in result else '❌'} {desc}: '{path}' → '{result}'")

print("\n" + "=" * 60)
print("TESTS COMPLETE")
print("=" * 60)
