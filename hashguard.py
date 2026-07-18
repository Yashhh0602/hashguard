import hashlib
import json
import os
import time
import bcrypt

BASELINE_FILE = "baseline.json"


def compute_sha256(filepath):
    """Compute SHA256 hash of a file's contents."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def create_baseline(directory):
    """Scan a directory and store SHA256 hashes as a trusted baseline."""
    baseline = {}
    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            baseline[path] = {
    "hash": compute_sha256(path),
    "size": os.path.getsize(path),
}
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"Baseline created: {len(baseline)} files hashed.")


def check_integrity(directory):
    """Compare current file hashes against the stored baseline."""
    if not os.path.exists(BASELINE_FILE):
        print("No baseline found. Run create_baseline first.")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    current_files = set()
    tampered, missing, new = [], [], []

    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            current_files.add(path)
            current_hash = compute_sha256(path)

            if path not in baseline:
                new.append(path)
            elif baseline[path]["hash"] != current_hash:
                tampered.append(path)

    missing = [p for p in baseline if p not in current_files]

    print(f"\nIntegrity check on '{directory}':")
    print(f"  Tampered: {len(tampered)}")
    for p in tampered:
        print(f"    ⚠ {p}")
    print(f"  Missing:  {len(missing)}")
    for p in missing:
        print(f"    ✗ {p}")
    print(f"  New:      {len(new)}")
    for p in new:
        print(f"    + {p}")

    if not tampered and not missing and not new:
        print("  ✓ All files match baseline.")


def demo_why_sha256_is_wrong_for_passwords():
    """
    Demonstrates the actual security reasoning: SHA256 is FAST — great for
    file integrity, terrible for passwords, because fast hashing means an
    attacker with a leaked hash database can brute-force millions of
    guesses per second. bcrypt is deliberately SLOW to make brute-forcing
    computationally expensive, even at scale.
    """
    password = b"correcthorsebatterystaple"

    # SHA256 — fast, deterministic, no salt by default
    start = time.perf_counter()
    for _ in range(100_000):
        hashlib.sha256(password).hexdigest()
    sha_time = time.perf_counter() - start

    # bcrypt — deliberately slow, includes salt + configurable work factor
    start = time.perf_counter()
    hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))
    bcrypt_time = time.perf_counter() - start

    print("\n--- Why SHA256 is wrong for passwords ---")
    print(f"100,000 SHA256 hashes took: {sha_time:.4f}s "
          f"(~{100_000/sha_time:,.0f} hashes/sec)")
    print(f"ONE bcrypt hash (12 rounds) took: {bcrypt_time:.4f}s")
    print(
        "\nAn attacker with a leaked SHA256 password database could try "
        f"~{100_000/sha_time:,.0f} guesses/sec per core. With bcrypt's cost "
        "factor, that drops to roughly "
        f"{1/bcrypt_time:.1f} guesses/sec per core — bcrypt is designed to "
        "stay slow even as hardware gets faster, by increasing the work "
        "factor. SHA256 has no such knob; it just gets faster to brute-force "
        "every year GPUs improve."
    )

    # Verify bcrypt still works correctly
    is_valid = bcrypt.checkpw(password, hashed)
    print(f"\nbcrypt.checkpw() correctly verifies the password: {is_valid}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python hashguard.py baseline <directory>")
        print("  python hashguard.py check <directory>")
        print("  python hashguard.py demo")
        sys.exit(1)

    command = sys.argv[1]

    if command == "baseline":
        create_baseline(sys.argv[2])
    elif command == "check":
        check_integrity(sys.argv[2])
    elif command == "demo":
        demo_why_sha256_is_wrong_for_passwords()
    else:
        print(f"Unknown command: {command}")