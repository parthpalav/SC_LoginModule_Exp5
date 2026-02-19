"""
Breach Simulation Script
========================

PHASE 4: BREACH SIMULATION
===========================
This script simulates a database breach scenario to demonstrate
the difference between plaintext and hashed password storage.

Scenario:
---------
An attacker has gained unauthorized access to the users.json file.
This script shows what information they can extract and how quickly.

Run this script with: python breach_simulation.py

Educational Purpose:
-------------------
This demonstrates why password hashing is critical for security.
In production systems, even hashed passwords require additional
protections (rate limiting, intrusion detection, encryption at rest).
"""

import json
import os
import time
import bcrypt
from utils.file_handler import load_users

# Common passwords dictionary for attack simulation
COMMON_PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "admin",
    "welcome", "login", "princess", "solo", "starwars",
    "test123", "password123", "pass123", "demo", "user123"
]


def print_header(title):
    """Print a formatted section header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def print_breach_intro():
    """Print introduction to the breach simulation."""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*68 + "║")
    print("║" + "  🚨 DATABASE BREACH SIMULATION 🚨".center(68) + "║")
    print("║" + " "*68 + "║")
    print("╚" + "="*68 + "╝")
    print("\nScenario: An attacker has gained access to users.json")
    print("This simulation shows what they can extract from the database.\n")
    input("Press ENTER to begin simulation...")


def simulate_file_access():
    """Simulate attacker gaining access to the database file."""
    print_header("STEP 1: Attacker Gains File Access")
    
    print("🔓 Attacker accesses users.json file...")
    time.sleep(1)
    
    if not os.path.exists("users.json"):
        print("❌ Error: users.json not found!")
        print("Please register some users first by running the Flask app.\n")
        return False
    
    print("✅ File access successful!")
    
    # Get file size
    file_size = os.path.getsize("users.json")
    print(f"📁 File size: {file_size} bytes")
    
    return True


def analyze_plaintext_users(users):
    """Analyze and display plaintext user data."""
    plaintext_users = [u for u in users if u.get('storage_method') == 'plaintext']
    
    if not plaintext_users:
        print("No plaintext users found in database.")
        return
    
    print_header("PLAINTEXT STORAGE ANALYSIS (INSECURE)")
    
    print(f"Found {len(plaintext_users)} users with PLAINTEXT passwords\n")
    print("⚠️  CRITICAL VULNERABILITY: Passwords are stored in readable form!\n")
    
    print("Extracted credentials (INSTANTLY):")
    print("-" * 70)
    print(f"{'Username':<20} {'Password':<30} {'Length':<10}")
    print("-" * 70)
    
    for user in plaintext_users:
        username = user.get('username', 'N/A')
        password = user.get('password', 'N/A')
        length = len(password) if password != 'N/A' else 0
        
        print(f"{username:<20} {password:<30} {length:<10}")
    
    print("-" * 70)
    
    print(f"\n⚠️  RESULT: ALL {len(plaintext_users)} passwords compromised INSTANTLY!")
    print("⏱️  Time required: < 1 second")
    print("🔓 Attacker can now:")
    print("   • Log in to all accounts immediately")
    print("   • Try passwords on other websites (credential stuffing)")
    print("   • Sell credentials on dark web")
    print("   • Blackmail users")


def attempt_dictionary_attack_hashed(users):
    """Simulate dictionary attack on hashed passwords."""
    hashed_users = [u for u in users if u.get('storage_method') == 'bcrypt']
    
    if not hashed_users:
        print("No hashed users found in database.")
        return
    
    print_header("BCRYPT HASHED STORAGE ANALYSIS (SECURE)")
    
    print(f"Found {len(hashed_users)} users with BCRYPT hashed passwords\n")
    print("✅ SECURE: Passwords are hashed with automatic salting\n")
    
    print("Stored hashes (attacker sees this):")
    print("-" * 70)
    
    for user in hashed_users:
        username = user.get('username', 'N/A')
        hash_value = user.get('password_hash', 'N/A')
        
        print(f"User: {username}")
        print(f"Hash: {hash_value}")
        print(f"      └─ Algorithm: bcrypt (slow, salted)")
        print()
    
    print("-" * 70)
    print("\n🔨 Attempting dictionary attack with common passwords...")
    print(f"📚 Testing {len(COMMON_PASSWORDS)} common passwords...\n")
    
    cracked = []
    start_time = time.time()
    
    for user in hashed_users:
        username = user.get('username', 'N/A')
        stored_hash = user.get('password_hash', '')
        
        print(f"🎯 Attacking user '{username}'...")
        
        # Try each password in dictionary
        for i, password in enumerate(COMMON_PASSWORDS):
            try:
                # Simulate real attack - this is computationally expensive
                password_bytes = password.encode('utf-8')
                hash_bytes = stored_hash.encode('utf-8')
                
                if bcrypt.checkpw(password_bytes, hash_bytes):
                    cracked.append({
                        'username': username,
                        'password': password,
                        'attempts': i + 1
                    })
                    print(f"   ⚠️  CRACKED! Password: '{password}' (after {i+1} attempts)")
                    break
            except:
                pass
        else:
            print(f"   ✅ SECURE: Password not in common dictionary")
    
    elapsed_time = time.time() - start_time
    
    print("\n" + "-" * 70)
    print(f"⏱️  Attack duration: {elapsed_time:.2f} seconds")
    print(f"🔓 Passwords cracked: {len(cracked)} / {len(hashed_users)}")
    
    if cracked:
        print("\n⚠️  Cracked accounts (had weak passwords):")
        for item in cracked:
            print(f"   • {item['username']}: '{item['password']}'")
    
    if len(cracked) < len(hashed_users):
        secure_count = len(hashed_users) - len(cracked)
        print(f"\n✅ {secure_count} account(s) remain secure!")
        print("   These passwords were strong enough to resist the dictionary attack.")


def demonstrate_hash_properties():
    """Demonstrate key properties of bcrypt hashing."""
    print_header("DEMONSTRATING BCRYPT SECURITY PROPERTIES")
    
    print("🔬 Property 1: ONE-WAY FUNCTION")
    print("-" * 70)
    print("Hash → Password: IMPOSSIBLE (computationally infeasible)")
    print("Attacker cannot reverse a hash to get the original password.\n")
    
    print("🔬 Property 2: UNIQUE SALTS")
    print("-" * 70)
    print("Same password → Different hashes (due to random salts)")
    
    test_password = "testpassword"
    hash1 = bcrypt.hashpw(test_password.encode(), bcrypt.gensalt()).decode()
    hash2 = bcrypt.hashpw(test_password.encode(), bcrypt.gensalt()).decode()
    
    print(f"\nPassword: '{test_password}'")
    print(f"Hash 1:   {hash1}")
    print(f"Hash 2:   {hash2}")
    print(f"Match:    {hash1 == hash2} ← Hashes are different!\n")
    
    print("🔬 Property 3: COMPUTATIONAL COST")
    print("-" * 70)
    print("Bcrypt is intentionally SLOW to compute.")
    print("This makes brute-force attacks very time-consuming.\n")
    
    print("⏱️  Measuring hash speed...")
    start = time.time()
    bcrypt.hashpw(test_password.encode(), bcrypt.gensalt())
    duration = time.time() - start
    
    print(f"Single hash time: {duration*1000:.2f} ms")
    print(f"Maximum hash rate: ~{int(1/duration)} hashes/second")
    print(f"\n💡 Result: Attacker would need:")
    print(f"   • ~12 days to try 1 million passwords for ONE user")
    print(f"   • ~32 years to try 1 billion passwords for ONE user")


def print_comparison_summary():
    """Print final comparison between plaintext and hashed storage."""
    print_header("FINAL COMPARISON: PLAINTEXT vs BCRYPT")
    
    print("┌" + "─"*68 + "┐")
    print("│" + " PLAINTEXT STORAGE (INSECURE)".center(68) + "│")
    print("├" + "─"*68 + "┤")
    print("│  ❌ Passwords visible immediately                                  │")
    print("│  ❌ No protection against attacks                                  │")
    print("│  ❌ 100% success rate for attacker                                 │")
    print("│  ❌ All accounts compromised instantly                             │")
    print("│  ❌ Users endangered on other sites                                │")
    print("│  ⏱️  Breach time: < 1 second                                       │")
    print("└" + "─"*68 + "┘")
    
    print()
    
    print("┌" + "─"*68 + "┐")
    print("│" + " BCRYPT HASHING (SECURE)".center(68) + "│")
    print("├" + "─"*68 + "┤")
    print("│  ✅ Passwords protected by one-way hashing                         │")
    print("│  ✅ Each password has unique salt                                  │")
    print("│  ✅ Resistant to rainbow table attacks                             │")
    print("│  ✅ Computationally expensive to crack                             │")
    print("│  ✅ Strong passwords remain secure                                 │")
    print("│  ⏱️  Breach time: Years to decades for strong passwords            │")
    print("└" + "─"*68 + "┘")
    
    print("\n📚 KEY TAKEAWAYS:")
    print("   1. NEVER store passwords in plaintext")
    print("   2. Always use bcrypt (or similar) for password hashing")
    print("   3. Hashing is not optional - it's a security requirement")
    print("   4. Strong passwords still matter even with hashing")
    print("   5. Multiple security layers provide defense in depth")


def main():
    """Main simulation function."""
    print_breach_intro()
    
    # Step 1: Simulate file access
    if not simulate_file_access():
        return
    
    print("\n⏳ Loading user database...")
    time.sleep(1)
    
    # Load users from file
    users = load_users()
    
    if not users:
        print("\n❌ No users found in database!")
        print("Please register some users first using the Flask app.\n")
        return
    
    print(f"✅ Loaded {len(users)} user(s) from database\n")
    time.sleep(1)
    
    # Step 2: Analyze plaintext users (if any)
    analyze_plaintext_users(users)
    
    if any(u.get('storage_method') == 'plaintext' for u in users):
        print("\n" + "⚠️ "*35)
        input("\nPress ENTER to continue to hashed password analysis...")
    
    # Step 3: Attempt dictionary attack on hashed passwords
    attempt_dictionary_attack_hashed(users)
    
    input("\n\nPress ENTER to see bcrypt properties demonstration...")
    
    # Step 4: Demonstrate hash properties
    demonstrate_hash_properties()
    
    input("\nPress ENTER to see final comparison...")
    
    # Step 5: Show comparison summary
    print_comparison_summary()
    
    print("\n" + "="*70)
    print("  Simulation Complete")
    print("="*70)
    print("\n💡 Experiment with the application:")
    print("   • Register users with plaintext mode (change AUTH_MODE in app.py)")
    print("   • Register users with bcrypt mode (default)")
    print("   • Run this simulation again to see the difference")
    print("   • Check users.json to see how passwords are stored\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Simulation interrupted by user.\n")
    except Exception as e:
        print(f"\n❌ Error during simulation: {e}\n")
