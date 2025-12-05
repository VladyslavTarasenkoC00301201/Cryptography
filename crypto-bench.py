import os
import time
import csv

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


DEV_MODE = False

# ===== Global settings =====

PLAINTEXT_SIZE = 10 * 1024  # 10 KiB
REPEATS = 3 if DEV_MODE else 11                # we'll ignore the first timing

# Approximate mapping from security level to key size / curve
RSA_KEY_SIZES = {
    80: 1024,
    112: 2048,
    128: 3072,
    192: 7680,
    256: 15360,
}

# DSA is only standardised for certain key sizes, so we stop at ~128-bit security
DSA_KEY_SIZES = {
    80: 1024,
    112: 2048,
    128: 3072,
}

ECC_CURVES = {
    #80: ec.SECP160R2(), 80-bit ECC not used  here(no SECP160R2 in this library version)
    112: ec.SECP224R1(),
    128: ec.SECP256R1(),
    192: ec.SECP384R1(),
    256: ec.SECP521R1(),
}


AES_KEY_SIZES = [128, 192, 256]

# ===== Helper functions =====

def random_message(size: int = PLAINTEXT_SIZE) -> bytes:
    """Return a random message of `size` bytes."""
    return os.urandom(size)


def benchmark(fn, repeats: int = REPEATS) -> float:
    """
    Run fn() multiple times, ignore the first run,
    and return the average time in milliseconds.
    """
    times_ms = []
    for i in range(repeats):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        elapsed_ms = (t1 - t0) * 1000.0
        times_ms.append(elapsed_ms)

    # ignore the first measurement
    if len(times_ms) <= 1:
        return 0.0

    return sum(times_ms[1:]) / (len(times_ms) - 1)


def write_csv(filename: str, header: list[str], rows: list[dict]) -> None:
    """Write a list of dicts (rows) to a CSV file with the given header."""
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# ===== Key generation benchmarking =====

def generate_and_benchmark_keys():
    """
    Generate RSA, DSA, and ECC key pairs at various security levels,
    benchmark key generation time, and return:

    - keys: dict with keys["RSA"][sec] = private_key, etc.
    - results: list of dicts suitable for CSV output.
    """
    backend = default_backend()
    keys = {
        "RSA": {},
        "DSA": {},
        "ECC": {},
    }
    results = []

    # --- RSA ---
    for sec, size in RSA_KEY_SIZES.items():
        if DEV_MODE and sec > 128:
            continue
        def run():
            rsa.generate_private_key(
                public_exponent=65537,
                key_size=size,
                backend=backend,
            )

        avg_ms = benchmark(run)

        # generate one key to keep for later benchmarks
        priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=backend,
        )
        keys["RSA"][sec] = priv

        results.append({
            "algorithm": "RSA",
            "security_bits": sec,
            "key_size_bits": size,
            "curve": "",          # not applicable
            "avg_ms": avg_ms,
        })

    # --- DSA ---
    for sec, size in DSA_KEY_SIZES.items():
        def run():
            dsa.generate_private_key(
                key_size=size,
                backend=backend,
            )

        avg_ms = benchmark(run)

        priv = dsa.generate_private_key(
            key_size=size,
            backend=backend,
        )
        keys["DSA"][sec] = priv

        results.append({
            "algorithm": "DSA",
            "security_bits": sec,
            "key_size_bits": size,
            "curve": "",          # not applicable
            "avg_ms": avg_ms,
        })

    # --- ECC ---
    for sec, curve in ECC_CURVES.items():
        def run():
            ec.generate_private_key(
                curve=curve,
                backend=backend,
            )

        avg_ms = benchmark(run)

        priv = ec.generate_private_key(
            curve=curve,
            backend=backend,
        )
        keys["ECC"][sec] = priv

        results.append({
            "algorithm": "ECC",
            "security_bits": sec,
            "key_size_bits": "",  # not directly used here
            "curve": curve.name,
            "avg_ms": avg_ms,
        })

    return keys, results


# ===== Symmetric encryption / decryption (AES + ChaCha20) =====

def benchmark_symmetric(plaintext: bytes):
    """
    Benchmark AES (128/192/256) and ChaCha20 encryption and decryption
    on the given plaintext.

    Returns:
        encrypt_results: list[dict]
        decrypt_results: list[dict]
    """
    encrypt_results = []
    decrypt_results = []

    # --- AES (CTR mode) ---
    for key_bits in AES_KEY_SIZES:
        key_bytes = key_bits // 8

        # Prepare a fixed key/iv and ciphertext for the decryption benchmark
        key = os.urandom(key_bytes)
        iv = os.urandom(16)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CTR(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Encryption benchmark: new random key+iv each time
        def enc_run():
            k = os.urandom(key_bytes)
            iv_local = os.urandom(16)
            cipher_local = Cipher(
                algorithms.AES(k),
                modes.CTR(iv_local),
                backend=default_backend(),
            )
            enc = cipher_local.encryptor()
            _ = enc.update(plaintext) + enc.finalize()

        # Decryption benchmark: fixed key+iv, fixed ciphertext
        def dec_run():
            cipher_local = Cipher(
                algorithms.AES(key),
                modes.CTR(iv),
                backend=default_backend(),
            )
            dec = cipher_local.decryptor()
            _ = dec.update(ciphertext) + dec.finalize()

        enc_ms = benchmark(enc_run)
        dec_ms = benchmark(dec_run)

        encrypt_results.append({
            "algorithm": "AES",
            "key_bits": key_bits,
            "avg_ms": enc_ms,
        })
        decrypt_results.append({
            "algorithm": "AES",
            "key_bits": key_bits,
            "avg_ms": dec_ms,
        })

    # --- ChaCha20 (256-bit key) ---
    key = os.urandom(32)   # 256-bit key
    nonce = os.urandom(16)

    cipher = Cipher(
        algorithms.ChaCha20(key, nonce),
        mode=None,
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    def chacha_enc_run():
        k = os.urandom(32)
        nonce_local = os.urandom(16)
        cipher_local = Cipher(
            algorithms.ChaCha20(k, nonce_local),
            mode=None,
            backend=default_backend(),
        )
        enc = cipher_local.encryptor()
        _ = enc.update(plaintext) + enc.finalize()

    def chacha_dec_run():
        cipher_local = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=default_backend(),
        )
        dec = cipher_local.decryptor()
        _ = dec.update(ciphertext) + dec.finalize()

    chacha_enc_ms = benchmark(chacha_enc_run)
    chacha_dec_ms = benchmark(chacha_dec_run)

    encrypt_results.append({
        "algorithm": "ChaCha20",
        "key_bits": 256,
        "avg_ms": chacha_enc_ms,
    })
    decrypt_results.append({
        "algorithm": "ChaCha20",
        "key_bits": 256,
        "avg_ms": chacha_dec_ms,
    })

    return encrypt_results, decrypt_results


# ===== RSA encryption / decryption on 10 KiB (chunked) =====

def rsa_encrypt_large(message: bytes, public_key):
    """
    Encrypt a large message with RSA by chunking, using OAEP+SHA-256.
    """
    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    key_size_bytes = public_key.key_size // 8
    hash_len = hashes.SHA256().digest_size
    max_chunk = key_size_bytes - 2 * hash_len - 2

    ciphertext_chunks = []
    for i in range(0, len(message), max_chunk):
        chunk = message[i:i + max_chunk]
        ciphertext_chunks.append(public_key.encrypt(chunk, pad))
    return b"".join(ciphertext_chunks)


def rsa_decrypt_large(ciphertext: bytes, private_key):
    """
    Decrypt a large message that was encrypted with rsa_encrypt_large().
    """
    pad = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    key_size_bytes = private_key.key_size // 8

    plaintext_chunks = []
    for i in range(0, len(ciphertext), key_size_bytes):
        chunk = ciphertext[i:i + key_size_bytes]
        plaintext_chunks.append(private_key.decrypt(chunk, pad))
    return b"".join(plaintext_chunks)


def benchmark_rsa_enc_dec(plaintext: bytes, rsa_keys: dict):
    """
    Benchmark RSA encryption and decryption on the given plaintext
    for each RSA security level.

    rsa_keys: keys["RSA"] from generate_and_benchmark_keys()
              mapping security_bits -> private_key
    """
    encrypt_results = []
    decrypt_results = []

    for sec, priv in rsa_keys.items():
        pub = priv.public_key()

        # Prepare ciphertext once for decryption benchmark
        ciphertext = rsa_encrypt_large(plaintext, pub)

        def enc_run():
            _ = rsa_encrypt_large(plaintext, pub)

        def dec_run():
            _ = rsa_decrypt_large(ciphertext, priv)

        enc_ms = benchmark(enc_run)
        dec_ms = benchmark(dec_run)

        encrypt_results.append({
            "algorithm": "RSA",
            "security_bits": sec,
            "key_size_bits": priv.key_size,
            "key_bits": "",  # not used for RSA here
            "avg_ms": enc_ms,
        })
        decrypt_results.append({
            "algorithm": "RSA",
            "security_bits": sec,
            "key_size_bits": priv.key_size,
            "key_bits": "",  # not used for RSA here
            "avg_ms": dec_ms,
        })

    return encrypt_results, decrypt_results


# ===== Digital signing & verification (RSA, DSA, ECC) =====

def make_hash(message: bytes, hash_alg=None):
    """
    Hash the message with the given algorithm (default SHA-256).
    Returns (digest_bytes, hash_algorithm_object).
    """
    if hash_alg is None:
        hash_alg = hashes.SHA256()

    digest = hashes.Hash(hash_alg, backend=default_backend())
    digest.update(message)
    return digest.finalize(), hash_alg


def benchmark_sign_verify(message: bytes, keys: dict):
    """
    Benchmark signing and verification for RSA, DSA, ECC.

    keys: the dict returned by generate_and_benchmark_keys()
          keys["RSA"][sec] = private_key, etc.
    """
    sign_results = []
    verify_results = []

    msg_hash, hash_alg = make_hash(message)

    for algo_name, key_dict in keys.items():
        for sec, priv in key_dict.items():
            pub = priv.public_key()

            # prepare one signature for the verify benchmark
            if algo_name == "RSA":
                signature = priv.sign(
                    msg_hash,
                    padding.PKCS1v15(),
                    utils.Prehashed(hash_alg),
                )

                def sign_run():
                    _ = priv.sign(
                        msg_hash,
                        padding.PKCS1v15(),
                        utils.Prehashed(hash_alg),
                    )

                def verify_run():
                    pub.verify(
                        signature,
                        msg_hash,
                        padding.PKCS1v15(),
                        utils.Prehashed(hash_alg),
                    )

            elif algo_name == "DSA":
                signature = priv.sign(
                    msg_hash,
                    utils.Prehashed(hash_alg),
                )

                def sign_run():
                    _ = priv.sign(
                        msg_hash,
                        utils.Prehashed(hash_alg),
                    )

                def verify_run():
                    pub.verify(
                        signature,
                        msg_hash,
                        utils.Prehashed(hash_alg),
                    )

            elif algo_name == "ECC":
                signature = priv.sign(
                    msg_hash,
                    ec.ECDSA(utils.Prehashed(hash_alg)),
                )

                def sign_run():
                    _ = priv.sign(
                        msg_hash,
                        ec.ECDSA(utils.Prehashed(hash_alg)),
                    )

                def verify_run():
                    pub.verify(
                        signature,
                        msg_hash,
                        ec.ECDSA(utils.Prehashed(hash_alg)),
                    )

            else:
                # shouldn't happen, but just in case
                continue

            sign_ms = benchmark(sign_run)
            verify_ms = benchmark(verify_run)

            sign_results.append({
                "algorithm": algo_name,
                "security_bits": sec,
                "avg_ms": sign_ms,
                "hash": hash_alg.name,
            })
            verify_results.append({
                "algorithm": algo_name,
                "security_bits": sec,
                "avg_ms": verify_ms,
                "hash": hash_alg.name,
            })

    return sign_results, verify_results



def main():
    print("=== Crypto benchmark: key generation + symmetric + RSA stage ===")

    # 10 KiB random message for all benchmarks
    msg = random_message()
    print(f"Random message length: {len(msg)} bytes")

    # --- Key generation ---
    print("Generating keys and benchmarking key generation...")
    keys, keygen_results = generate_and_benchmark_keys()
    print(f"Generated keys for: {list(keys.keys())}")

    write_csv(
        "keygen_results.csv",
        ["algorithm", "security_bits", "key_size_bits", "curve", "avg_ms"],
        keygen_results,
    )
    print("Wrote keygen_results.csv with", len(keygen_results), "rows")

    # --- Symmetric encryption / decryption ---
    print("Benchmarking symmetric encryption/decryption (AES + ChaCha20)...")
    sym_enc_results, sym_dec_results = benchmark_symmetric(msg)

    write_csv(
        "symmetric_encryption_results.csv",
        ["algorithm", "key_bits", "avg_ms"],
        sym_enc_results,
    )
    write_csv(
        "symmetric_decryption_results.csv",
        ["algorithm", "key_bits", "avg_ms"],
        sym_dec_results,
    )
    print("Wrote symmetric_encryption_results.csv with",
          len(sym_enc_results), "rows")
    print("Wrote symmetric_decryption_results.csv with",
          len(sym_dec_results), "rows")

    # --- RSA encryption / decryption ---
    print("Benchmarking RSA encryption/decryption on 10 KiB message...")
    rsa_enc_results, rsa_dec_results = benchmark_rsa_enc_dec(msg, keys["RSA"])
    print("RSA encryption/dec results for",
          len(rsa_enc_results), "security levels")

    # Build combined encryption/decryption CSVs (symmetric + RSA)
    combined_enc = []
    combined_dec = []

    # Symmetric rows → combined format
    for row in sym_enc_results:
        combined_enc.append({
            "algorithm": row["algorithm"],
            "security_bits": "",
            "key_size_bits": "",
            "key_bits": row["key_bits"],
            "avg_ms": row["avg_ms"],
        })

    for row in sym_dec_results:
        combined_dec.append({
            "algorithm": row["algorithm"],
            "security_bits": "",
            "key_size_bits": "",
            "key_bits": row["key_bits"],
            "avg_ms": row["avg_ms"],
        })

    # Add RSA rows (already in combined format)
    combined_enc.extend(rsa_enc_results)
    combined_dec.extend(rsa_dec_results)

    write_csv(
        "encryption_results.csv",
        ["algorithm", "security_bits", "key_size_bits", "key_bits", "avg_ms"],
        combined_enc,
    )
    write_csv(
        "decryption_results.csv",
        ["algorithm", "security_bits", "key_size_bits", "key_bits", "avg_ms"],
        combined_dec,
    )

    print("Wrote encryption_results.csv with", len(combined_enc), "rows")
    print("Wrote decryption_results.csv with", len(combined_dec), "rows")

    # --- Signing & verification ---
    print("Benchmarking digital signing and verification (RSA, DSA, ECC)...")
    sign_results, verify_results = benchmark_sign_verify(msg, keys)

    write_csv(
        "sign_results.csv",
        ["algorithm", "security_bits", "avg_ms", "hash"],
        sign_results,
    )
    write_csv(
        "verify_results.csv",
        ["algorithm", "security_bits", "avg_ms", "hash"],
        verify_results,
    )

    print("Wrote sign_results.csv with", len(sign_results), "rows")
    print("Wrote verify_results.csv with", len(verify_results), "rows")
 


if __name__ == "__main__":
    main()
    

