# 🔐 Encryption & Hashing Reference Guide

**Data Security System - Complete Cryptographic Specification**

---

## 📋 Table of Contents

1. [Password Hashing](#password-hashing)
2. [Data Encryption](#data-encryption)
3. [End-to-End Encryption](#end-to-end-encryption)
4. [Sensitive Data Protection](#sensitive-data-protection)
5. [Key Derivation](#key-derivation)
6. [Data Processing Flow](#data-processing-flow)

---

## 🔑 Password Hashing

### Multi-Layer Password Vault (5 Layers)

**Storage Format:**
```
$MLP$v1$[salt_b64]$[pepper_id]$[argon2_params]$[encrypted_hmac_hash_b64]
```

**Processing Pipeline:**

1. **Layer 1: Pepper Application**
   ```
   peppered_password = password ⊕ SYSTEM_PEPPER
   ```
   - Adds server-side secret to password

2. **Layer 2: Argon2id Hashing**
   ```
   argon2_hash = Argon2id(peppered_password, salt, m=128MB, t=4, p=8)
   → 512-bit hash output
   ```
   - Memory: 131,072 KB (128 MB)
   - Iterations: 4
   - Parallelism: 8 threads
   - Salt: 32 bytes (256-bit)
   - Output: 64 bytes (512-bit)

3. **Layer 3: AES-256-GCM Encryption**
   ```
   encryption_key = PBKDF2-HMAC-SHA512(salt, 600,000 iterations)
   encrypted_hash = AES-256-GCM(argon2_hash, encryption_key, iv)
   ```
   - Key size: 256-bit
   - IV: 12 bytes (96-bit)
   - Tag: 128-bit authentication tag

4. **Layer 4: HMAC-SHA512 Signature**
   ```
   hmac_key = PBKDF2-HMAC-SHA512(salt, 600,000 iterations)
   signature = HMAC-SHA512(encrypted_hash, hmac_key)
   ```
   - Output: 64 bytes (512-bit)

5. **Layer 5: Combined Storage**
   ```
   final_output = encrypted_hash || hmac_signature
   ```

### Legacy Argon2id (Fallback)

**Formula:**
```
hash = Argon2id(password, salt, m=131072, t=4, p=8)
```

**Encoded Format:**
```
$argon2id$v=19$m=131072,t=4,p=8$[salt_b64]$[hash_b64]
```

**Parameters:**
- Version: 19 (Argon2 v1.3)
- Memory: 131,072 KB (128 MB)
- Iterations: 4 (time cost)
- Parallelism: 8 threads
- Salt: 32 bytes
- Hash output: 64 bytes

---

## 🔒 Data Encryption

### AES-256-GCM (Authenticated Encryption)

**Encryption Formula:**
```
ciphertext = AES-256-GCM(plaintext, key, iv)
output = iv || ciphertext || tag
```

**Parameters:**
- Algorithm: AES/GCM/NoPadding
- Key size: 256-bit
- IV length: 12 bytes (96-bit)
- Tag length: 128-bit (authentication)
- Mode: Galois/Counter Mode (GCM)

**Format:**
```
[12-byte IV][ciphertext][16-byte auth tag]
```

**Security Properties:**
- ✅ Confidentiality (encryption)
- ✅ Integrity (authentication tag)
- ✅ AEAD (Authenticated Encryption with Associated Data)

---

## 🌐 End-to-End Encryption

### ECDH Key Exchange

**Curve:** P-384 (secp384r1)  
**Security Level:** 192-bit

**Key Generation:**
```
(private_key, public_key) = ECDH_KeyGen(P-384)
```

**Shared Secret Derivation:**
```
shared_secret = ECDH(our_private_key, peer_public_key)
derived_key = HKDF-Extract-Expand(shared_secret, "E2E-AES-KEY", 32)
```

### HKDF (HMAC-based Key Derivation)

**Extract Phase:**
```
PRK = HMAC-SHA384(zero_salt, input_key_material)
```

**Expand Phase:**
```
OKM = HMAC-SHA384(PRK, info || 0x01)
key = first_32_bytes(OKM)
```

### Hybrid Encryption (ECIES-style)

**Encryption:**
```
ephemeral_keypair = generate_keypair()
shared_secret = ECDH(ephemeral_private, recipient_public)
aes_key = HKDF(shared_secret)
ciphertext = AES-256-GCM(plaintext, aes_key)
output = ephemeral_public || iv || ciphertext || tag
```

**Format:**
```
[97-byte ephemeral_public][12-byte iv][ciphertext][16-byte tag]
```

---

## 🛡️ Sensitive Data Protection

### Field-Level Encryption

**Encryption:**
```
encrypted_field = "ENC$v1$" + Base64(AES-256-GCM(plaintext, key))
```

**Decryption:**
```
Parse format → Extract ciphertext → AES-256-GCM decrypt
```

### Searchable Encryption (Blind Index)

**Blind Index Formula:**
```
normalized_input = lowercase(trim(plaintext))
blind_index = Truncate(HMAC-SHA256(normalized_input, index_key), 16)
output = Base64(blind_index)
```

**Properties:**
- Allows searching without decryption
- ⚠️ Leaks search patterns (use carefully)
- Index size: 16 bytes (128-bit)

### Data Masking

**Email Masking:**
```
"user@example.com" → "us****@example.com"
Keep: first 2 chars + domain
```

**Phone Masking:**
```
"1234567890" → "123*****90"
Keep: first 3 + last 2 digits
```

**ID Masking:**
```
"ID123456789" → "ID****6789"
Keep: prefix + last 4 chars
```

---

## 🔑 Key Derivation

### PBKDF2-HMAC-SHA512

**Formula:**
```
derived_key = PBKDF2-HMAC-SHA512(password, salt, iterations=600,000, keylen=32)
```

**Parameters:**
- Algorithm: PBKDF2 with HMAC-SHA512
- Iterations: 600,000 (OWASP 2024 recommendation)
- Salt: 32 bytes (256-bit)
- Output: 32 bytes (256-bit key)

**Use Cases:**
- Password-based encryption keys
- Database password encryption
- AES key derivation

### HMAC-SHA512 Signature

**Formula:**
```
signature = HMAC-SHA512(message, key)
```

**Properties:**
- Output: 64 bytes (512-bit)
- Used for message authentication
- Constant-time verification (timing attack resistant)

---

## 📊 Data Processing Flow

### User Registration Flow

```
1. User enters password
   ↓
2. Multi-Layer Vault Processing:
   password → pepper → Argon2id → AES-GCM → HMAC → storage
   ↓
3. Store in database:
   $MLP$v1$[salt]$[pepper_id]$[params]$[encrypted_hash]
```

### User Login Flow

```
1. User enters password
   ↓
2. Retrieve stored hash from database
   ↓
3. Verify:
   - Extract salt and parameters
   - Recompute: pepper → Argon2id → encrypt → HMAC
   - Compare: constant-time comparison
   ↓
4. Return: Match (✅) or No Match (❌)
```

### Sensitive Data Storage

```
1. User data (email, phone, etc.)
   ↓
2. Encrypt with AES-256-GCM
   ↓
3. Create blind index (if searchable)
   ↓
4. Store: "ENC$v1$[ciphertext]" + blind_index
   ↓
5. Database stores encrypted data
```

### Sensitive Data Retrieval

```
1. Query by blind index (if searching)
   ↓
2. Retrieve encrypted field
   ↓
3. Parse format: "ENC$v1$[ciphertext]"
   ↓
4. Decrypt with AES-256-GCM
   ↓
5. Return plaintext to authorized user
```

---

## 🔢 Cryptographic Constants Summary

| Component | Algorithm | Key Size | Parameters |
|-----------|-----------|----------|------------|
| **Password Hash** | Argon2id | - | m=128MB, t=4, p=8 |
| **Password Encrypt** | AES-256-GCM | 256-bit | IV=12B, Tag=128b |
| **Password HMAC** | HMAC-SHA512 | 512-bit | Output=64B |
| **Key Derivation** | PBKDF2-SHA512 | 256-bit | 600k iterations |
| **Data Encryption** | AES-256-GCM | 256-bit | IV=12B, Tag=128b |
| **E2E Key Exchange** | ECDH P-384 | 384-bit | 192-bit security |
| **E2E Encryption** | AES-256-GCM | 256-bit | Hybrid ECIES |
| **Blind Index** | HMAC-SHA256 | 256-bit | Truncated 128-bit |
| **Salt Generation** | SecureRandom | 256-bit | 32 bytes |

---

## 🎯 Security Strength Analysis

| Protection Type | Security Level | Notes |
|----------------|----------------|-------|
| Password Hashing | **Maximum** | 5-layer defense, memory-hard |
| Data at Rest | **Maximum** | AES-256-GCM authenticated |
| Data in Transit | **Maximum** | E2E with ECDH P-384 |
| Key Derivation | **Maximum** | 600k PBKDF2 iterations |
| Random Generation | **Cryptographic** | SecureRandom.getInstanceStrong() |

---

## 📝 What Gets Encrypted

### Passwords
- **Method:** Multi-Layer Password Vault (5 layers)
- **Storage:** Hash only (irreversible)
- **Verification:** Recompute and compare

### Sensitive User Data
- **Email addresses:** AES-256-GCM + Blind index
- **Phone numbers:** AES-256-GCM + Blind index
- **ID numbers:** AES-256-GCM + Masking
- **Personal information:** AES-256-GCM

### Database Credentials
- **Method:** PBKDF2-HMAC-SHA256 + AES
- **Iterations:** 310,000
- **Storage:** Environment variables (encrypted)

---

## 🔐 Security Features

1. **Timing Attack Prevention:** Constant-time comparisons
2. **Memory Safety:** Secure wiping of sensitive data
3. **Perfect Forward Secrecy:** Ephemeral keys in E2E
4. **Authenticated Encryption:** GCM mode with integrity tags
5. **Salt Uniqueness:** Cryptographically random per password
6. **Pepper Protection:** Server-side secret (not in database)
7. **Memory-Hard Hashing:** Argon2id resists GPU attacks
8. **AEAD:** Combined confidentiality + integrity

---

## 📐 Mathematical Notation

**Key Symbols:**
- `⊕` = XOR operation
- `||` = Concatenation
- `→` = Produces/Results in
- `HMAC(k, m)` = Hash-based Message Authentication Code
- `E(k, m)` = Encryption with key k and message m
- `D(k, c)` = Decryption with key k and ciphertext c
- `H(m)` = Hash function
- `KDF(p, s)` = Key Derivation Function with password p and salt s

---

## ✅ Compliance

- ✅ **OWASP 2024:** Password storage guidelines
- ✅ **NIST SP 800-63B:** Digital identity guidelines
- ✅ **FIPS 140-2:** Cryptographic module standards
- ✅ **PHC Winner:** Argon2 (Password Hashing Competition)
- ✅ **NSA Suite B:** P-384 curve approved

---

## 🛠️ Methods & Implementation Logic

### CryptoCore.java - Cryptographic Operations

| Method | Parameters | Returns | Logic Flow |
|--------|-----------|---------|------------|
| `encryptAesGcm()` | plaintext, key | ciphertext | 1. Generate random 12-byte IV<br>2. Configure GCM with 128-bit tag<br>3. Encrypt with AES-256-GCM<br>4. Prepend IV to ciphertext<br>5. Return [IV\|\|ciphertext\|\|tag] |
| `decryptAesGcm()` | ciphertext, key | plaintext | 1. Extract IV (first 12 bytes)<br>2. Extract encrypted data<br>3. Configure GCM parameters<br>4. Decrypt and verify tag<br>5. Return plaintext |
| `encryptToBase64()` | string, key | Base64 | 1. Convert string to UTF-8 bytes<br>2. Call encryptAesGcm()<br>3. Encode to Base64<br>4. Return encoded string |
| `decryptFromBase64()` | ciphertext, key | string | 1. Decode Base64<br>2. Call decryptAesGcm()<br>3. Convert bytes to UTF-8 string<br>4. Return plaintext |
| `deriveKey()` | password, salt, iterations | SecretKey | 1. Create PBKDF2-SHA512 factory<br>2. Configure key spec (256-bit output)<br>3. Generate secret with iterations<br>4. Wrap as AES key<br>5. Return SecretKey |
| `generateRandomKey()` | - | SecretKey | 1. Initialize KeyGenerator (AES)<br>2. Configure 256-bit size<br>3. Use SecureRandom<br>4. Generate key |
| `hmacSign()` | data, key | signature | 1. Initialize HMAC-SHA512<br>2. Set secret key<br>3. Process data<br>4. Return 64-byte signature |
| `hmacVerify()` | data, signature, key | boolean | 1. Compute HMAC of data<br>2. Constant-time compare with signature<br>3. Return match result |
| `generateSalt()` | - | byte[] | 1. Create 32-byte array<br>2. Fill with SecureRandom<br>3. Return salt |
| `generateSecureToken()` | byteLength | String | 1. Generate random bytes<br>2. Encode as URL-safe Base64<br>3. Return token |
| `constantTimeEquals()` | a[], b[] | boolean | 1. Check length equality<br>2. XOR all bytes<br>3. Check if result is zero<br>4. Prevents timing attacks |
| `wipeMemory()` | data[] | void | 1. Overwrite with random bytes<br>2. Fill with zeros<br>3. Clear sensitive data |
| `xorBytes()` | a[], b[] | byte[] | 1. Check length match<br>2. XOR each byte pair<br>3. Return result |
| `bytesToHex()` | bytes[] | String | 1. Iterate each byte<br>2. Format as 2-digit hex<br>3. Return hex string |

**CryptoCore Logic:**
- All encryption uses authenticated AES-256-GCM
- Random IVs prevent pattern detection
- Memory wiping protects against forensic recovery
- Constant-time operations prevent timing attacks

---

### E2EEncryption.java - End-to-End Encryption

| Method | Parameters | Returns | Logic Flow |
|--------|-----------|---------|------------|
| `generateKeyPair()` | - | KeyPair | 1. Initialize ECDH KeyPairGenerator<br>2. Configure P-384 curve<br>3. Generate key pair<br>4. Return (private, public) |
| `exportPublicKey()` | PublicKey | String | 1. Get key bytes (X.509 format)<br>2. Encode to Base64<br>3. Return encoded key |
| `importPublicKey()` | base64Key | PublicKey | 1. Decode Base64<br>2. Create X509EncodedKeySpec<br>3. Generate public key<br>4. Return PublicKey |
| `deriveSharedKey()` | privateKey, peerPublicKey | SecretKey | 1. Initialize ECDH KeyAgreement<br>2. Set private key<br>3. Perform key exchange (doPhase)<br>4. Generate shared secret<br>5. Apply HKDF<br>6. Wipe shared secret<br>7. Return AES key |
| `hkdfExtractExpand()` | inputKeyMaterial, info, length | byte[] | 1. **Extract:** HMAC-SHA384(zero_salt, IKM)<br>2. **Expand:** HMAC-SHA384(PRK, info\|\|0x01)<br>3. Truncate to length<br>4. Return derived key |
| `encryptForRecipient()` | plaintext, recipientPublicKey | String | 1. Generate ephemeral keypair<br>2. Derive shared secret via ECDH<br>3. Generate random IV<br>4. Encrypt with AES-256-GCM<br>5. Combine [ephemeral_pub\|\|IV\|\|ciphertext]<br>6. Encode to Base64 |
| `decryptWithPrivateKey()` | encryptedData, privateKey | String | 1. Decode Base64<br>2. Extract ephemeral public key<br>3. Extract IV and ciphertext<br>4. Reconstruct ephemeral key<br>5. Derive shared secret<br>6. Decrypt with AES-256-GCM<br>7. Return plaintext |
| `encryptSymmetric()` | plaintext, key | String | 1. Generate random IV<br>2. Configure AES-256-GCM<br>3. Encrypt plaintext<br>4. Prepend IV to ciphertext<br>5. Encode to Base64 |
| `decryptSymmetric()` | encryptedData, key | String | 1. Decode Base64<br>2. Extract IV (first 12 bytes)<br>3. Extract ciphertext<br>4. Decrypt with AES-256-GCM<br>5. Return plaintext |
| `encryptDeterministic()` | plaintext, key | String | 1. Hash plaintext with SHA-256<br>2. Use hash as deterministic IV<br>3. Encrypt with AES-256-GCM<br>4. Return ciphertext (same input → same output) |
| `encryptWithAAD()` | plaintext, key, aad | String | 1. Generate random IV<br>2. Configure GCM cipher<br>3. Add AAD (authenticated but not encrypted)<br>4. Encrypt plaintext<br>5. Return IV\|\|ciphertext\|\|tag |
| `decryptWithAAD()` | encryptedData, key, aad | String | 1. Decode and parse data<br>2. Extract IV and ciphertext<br>3. Configure cipher with AAD<br>4. Decrypt and verify integrity<br>5. Return plaintext |

**E2E Logic:**
- ECDH provides forward secrecy (ephemeral keys)
- Hybrid encryption combines asymmetric + symmetric
- P-384 curve provides 192-bit security level
- Perfect Forward Secrecy: each session has unique keys

---

### MultiLayerPasswordVault.java - 5-Layer Password Protection

| Method | Parameters | Returns | Logic Flow |
|--------|-----------|---------|------------|
| `hashPassword()` | password | String | 1. Generate 32-byte random salt<br>2. **Layer 1:** Apply pepper via HMAC<br>3. **Layer 2:** Hash with Argon2id<br>4. **Layer 3:** Derive encryption key (PBKDF2)<br>5. Encrypt hash with AES-256-GCM<br>6. **Layer 4:** Derive HMAC key (PBKDF2)<br>7. Sign encrypted hash<br>8. **Layer 5:** Combine all layers<br>9. Encode as $MLP$v1$...<br>10. Return encoded string |
| `verifyPassword()` | password, storedHash | boolean | 1. Parse MLP format<br>2. Extract salt, params, encrypted data<br>3. Split encrypted hash and HMAC<br>4. **Verify HMAC** (fail fast if tampered)<br>5. Derive encryption key<br>6. Decrypt stored hash<br>7. Recompute: pepper → Argon2id<br>8. **Constant-time compare** hashes<br>9. Return match result |
| `applyPepper()` | password | byte[] | 1. Initialize HMAC-SHA512<br>2. Use system pepper as key<br>3. Process password<br>4. Return peppered bytes |
| `argon2idHash()` | data, salt, memory, iterations, parallelism | byte[] | 1. Build Argon2id parameters<br>2. Set memory (128 MB)<br>3. Set iterations (4)<br>4. Set parallelism (8 threads)<br>5. Generate 64-byte hash<br>6. Return hash |
| `encryptAesGcm()` | plaintext, key | byte[] | 1. Generate random 12-byte IV<br>2. Configure GCM (128-bit tag)<br>3. Encrypt with AES-256<br>4. Prepend IV to ciphertext<br>5. Return encrypted data |
| `decryptAesGcm()` | ciphertext, key | byte[] | 1. Extract IV (first 12 bytes)<br>2. Extract encrypted data<br>3. Configure GCM cipher<br>4. Decrypt and verify tag<br>5. Return plaintext |
| `hmacSign()` | data, key | byte[] | 1. Initialize HMAC-SHA512<br>2. Process data with key<br>3. Return 64-byte signature |
| `deriveEncryptionKey()` | salt | SecretKey | 1. Combine pepper + "ENCRYPTION_KEY_DERIVATION"<br>2. Run PBKDF2-SHA512 (600k iterations)<br>3. Derive 256-bit key<br>4. Return AES key |
| `deriveHmacKey()` | salt | SecretKey | 1. Combine pepper + "HMAC_KEY_DERIVATION"<br>2. Run PBKDF2-SHA512 (600k iterations)<br>3. Derive 256-bit key<br>4. Return HMAC key |
| `verifyLegacyArgon2()` | password, encodedHash | boolean | 1. Parse Argon2id format<br>2. Extract parameters and salt<br>3. Recompute Argon2id hash<br>4. Constant-time compare<br>5. Return match result |

**Multi-Layer Vault Logic:**
1. **Pepper (Layer 1):** Server secret prevents rainbow tables
2. **Argon2id (Layer 2):** Memory-hard function resists GPUs
3. **AES Encryption (Layer 3):** Encrypts the hash itself
4. **HMAC (Layer 4):** Detects tampering
5. **PBKDF2 (Layer 5):** Derives encryption/HMAC keys

**Format:** `$MLP$v1$[salt]$[pepper_id]$[argon2_params]$[encrypted_hmac_hash]`

---

### PasswordSecurityUtil.java - Password Management

| Method | Parameters | Returns | Logic Flow |
|--------|-----------|---------|------------|
| `hashPassword()` | password | String | 1. Log hashing operation<br>2. If USE_MULTI_LAYER_VAULT enabled:<br>&nbsp;&nbsp;&nbsp;→ Call MultiLayerPasswordVault.hashPassword()<br>3. Else:<br>&nbsp;&nbsp;&nbsp;→ Call hashPasswordArgon2id()<br>4. Return encoded hash |
| `hashPasswordArgon2id()` | password | String | 1. Generate 32-byte random salt<br>2. Configure Argon2id:<br>&nbsp;&nbsp;&nbsp;• Memory: 128 MB<br>&nbsp;&nbsp;&nbsp;• Iterations: 4<br>&nbsp;&nbsp;&nbsp;• Parallelism: 8<br>3. Generate 64-byte hash<br>4. Encode as PHC format<br>5. Return $argon2id$v=19$... |
| `verifyPassword()` | password, encodedHash | boolean | 1. Detect hash format (MLP or Argon2id)<br>2. If MLP format:<br>&nbsp;&nbsp;&nbsp;→ Call MultiLayerPasswordVault.verifyPassword()<br>3. If Argon2id format:<br>&nbsp;&nbsp;&nbsp;→ Call verifyPasswordArgon2id()<br>4. Log verification attempt<br>5. Return match result |
| `verifyPasswordArgon2id()` | password, encodedHash | boolean | 1. Parse encoded hash ($argon2id$...)<br>2. Extract: memory, iterations, parallelism<br>3. Extract: salt and expected hash<br>4. Recompute Argon2id hash<br>5. Constant-time compare<br>6. Return match result |
| `needsRehash()` | encodedHash | boolean | 1. If MLP format: return false (strongest)<br>2. If Argon2id + vault enabled: return true<br>3. If Argon2id parameters outdated: return true<br>4. Otherwise: return false |
| `encodeHash()` | salt, hash | String | 1. Build PHC string format<br>2. Include version (v=19)<br>3. Include parameters (m, t, p)<br>4. Base64 encode salt<br>5. Base64 encode hash<br>6. Return formatted string |
| `constantTimeEquals()` | a[], b[] | boolean | 1. Check length equality<br>2. XOR all byte pairs<br>3. Check if result == 0<br>4. Prevents timing attacks |

**Password Security Logic:**
- Auto-detects hash format for backward compatibility
- Upgrades weak hashes after successful login
- Constant-time comparison prevents timing attacks
- Audit logging for security monitoring

---

### SensitiveDataProtector.java - PII Encryption

| Method | Parameters | Returns | Logic Flow |
|--------|-----------|---------|------------|
| `encryptField()` | plaintext | String | 1. Check if plaintext is null/empty<br>2. Call CryptoCore.encryptToBase64()<br>3. Prepend "ENC$v1$" prefix<br>4. Return formatted ciphertext |
| `decryptField()` | encryptedField | String | 1. Check if starts with "ENC$"<br>2. Parse format: split by '$'<br>3. Extract version and ciphertext<br>4. Call CryptoCore.decryptFromBase64()<br>5. Return plaintext |
| `createBlindIndex()` | plaintext | String | 1. Normalize input (lowercase, trim)<br>2. Compute HMAC-SHA256 with index key<br>3. Truncate to 16 bytes (128-bit)<br>4. Encode to Base64<br>5. Return index (allows searching) |
| `encryptSearchable()` | plaintext | EncryptedSearchableField | 1. Call encryptField() for ciphertext<br>2. Call createBlindIndex() for index<br>3. Return object with both values |
| `encryptEmail()` | email | EncryptedSearchableField | 1. Normalize email (lowercase, trim)<br>2. Call encryptSearchable()<br>3. Return encrypted value + blind index |
| `encryptPhoneNumber()` | phoneNumber | String | 1. Normalize: remove non-digits<br>2. Call encryptField()<br>3. Return encrypted phone |
| `encryptIdNumber()` | idNumber | EncryptedSearchableField | 1. Normalize: uppercase, remove special chars<br>2. Call encryptSearchable()<br>3. Return encrypted ID + index |
| `maskEmail()` | email | String | 1. Find @ symbol<br>2. Keep first 2 chars of local part<br>3. Replace rest with ***<br>4. Keep full domain<br>5. Return: "us***@example.com" |
| `maskPhoneNumber()` | phone | String | 1. Extract only digits<br>2. Keep last 4 digits<br>3. Replace rest with ***<br>4. Return: "***-***-1234" |
| `maskIdNumber()` | idNumber | String | 1. Keep last 4 characters<br>2. Replace rest with *<br>3. Return: "****6789" |
| `maskName()` | name | String | 1. Split by spaces<br>2. Keep first name full<br>3. Mask last name (first char + ***)<br>4. Return: "John D***" |
| `mightContainPII()` | data | boolean | 1. Check email regex pattern<br>2. Check phone regex pattern<br>3. Check SSN pattern<br>4. Check credit card pattern<br>5. Return true if any match |
| `redactPII()` | data | String | 1. Replace emails with [EMAIL REDACTED]<br>2. Replace phones with [PHONE REDACTED]<br>3. Replace SSN with [SSN REDACTED]<br>4. Replace cards with [CARD REDACTED]<br>5. Return sanitized string |
| `loadOrGenerateKey()` | keyName | SecretKey | 1. Check environment variable<br>2. If found: decode Base64<br>3. Else: generate deterministic key<br>4. Wrap as AES SecretKey<br>5. Return key |
| `generateNewKey()` | - | String | 1. Generate 32 random bytes<br>2. Encode to Base64<br>3. Return key string |

**Sensitive Data Logic:**
- Field encryption: "ENC$v1$[ciphertext]" format
- Blind index: HMAC-based searchable encryption
- Masking: Display-safe partial visibility
- PII detection: Regex-based pattern matching
- Redaction: Safe logging without exposing data

---

### PasswordEncryptor.java - Database Credential Encryption

| Method | Parameters | Returns | Logic Flow |
|--------|-----------|---------|------------|
| `main()` | args | void | 1. Prompt for MySQL password<br>2. Prompt for master key (32+ chars)<br>3. Generate random 16-byte salt<br>4. Derive encryption key via PBKDF2-SHA256<br>&nbsp;&nbsp;&nbsp;• 310,000 iterations<br>&nbsp;&nbsp;&nbsp;• 256-bit key<br>5. Encrypt password with AES<br>6. Encode to Base64<br>7. Display encrypted credentials<br>8. Show security warnings |

**Logic:**
- One-time utility to encrypt DB passwords
- Uses PBKDF2-SHA256 with 310k iterations
- Outputs: encrypted password, salt, master key
- Credentials stored as environment variables

---

## 📈 Complete Data Flow Diagrams

### User Registration Flow (Detailed)

```
┌─────────────────────────────────────────────────────────────────┐
│ USER INPUT: Password "MySecurePass123!"                         │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 1: PEPPER APPLICATION                                     │
│ • Method: applyPepper(password)                                 │
│ • Operation: HMAC-SHA512(password, SYSTEM_PEPPER)              │
│ • Output: 64-byte peppered password                            │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 2: ARGON2ID HASHING                                       │
│ • Method: argon2idHash(peppered_password, salt)                │
│ • Parameters: m=128MB, t=4, p=8, salt=32 bytes                 │
│ • Operation: Memory-hard password hashing                       │
│ • Output: 64-byte Argon2id hash                                │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 3: KEY DERIVATION                                         │
│ • Method: deriveEncryptionKey(salt)                            │
│ • Operation: PBKDF2-SHA512(pepper+purpose, salt, 600k iters)   │
│ • Output: 256-bit AES encryption key                           │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 3: AES-256-GCM ENCRYPTION                                 │
│ • Method: encryptAesGcm(argon2_hash, encryption_key)           │
│ • Operation: Generate IV → Encrypt with GCM → Add auth tag     │
│ • Output: [IV || encrypted_hash || tag]                        │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 4: HMAC SIGNATURE                                         │
│ • Method: deriveHmacKey(salt) + hmacSign(encrypted_hash, key)  │
│ • Operation: PBKDF2 key derivation → HMAC-SHA512 signing       │
│ • Output: 64-byte integrity signature                          │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 5: FINAL ENCODING                                         │
│ • Method: Combine all components                                │
│ • Format: $MLP$v1$[salt]$[pepper_v]$[params]$[enc+hmac]        │
│ • Store in database: users table, password_hash column         │
└─────────────────────────────────────────────────────────────────┘
```

### User Login Flow (Detailed)

```
┌─────────────────────────────────────────────────────────────────┐
│ USER INPUT: Login attempt with password                         │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: RETRIEVE STORED HASH                                    │
│ • Query database: SELECT password_hash FROM users WHERE...      │
│ • Method: UserDAO.getUserByUsername()                           │
│ • Result: $MLP$v1$... or $argon2id$...                         │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: FORMAT DETECTION                                        │
│ • Method: verifyPassword() auto-detects format                  │
│ • If MLP: → MultiLayerPasswordVault.verifyPassword()           │
│ • If Argon2id: → verifyPasswordArgon2id()                      │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: PARSE STORED HASH                                       │
│ • Split by '$' delimiter                                        │
│ • Extract: salt, pepper_version, argon2_params, encrypted_data │
│ • Parse parameters: memory, iterations, parallelism            │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: VERIFY HMAC (Fail Fast)                                 │
│ • Method: deriveHmacKey(salt) + constantTimeEquals()           │
│ • Split encrypted_data into: [encrypted_hash][hmac_signature]  │
│ • Compute HMAC of encrypted_hash                                │
│ • Compare with stored HMAC (constant-time)                      │
│ • If mismatch: RETURN FALSE (tampered data)                    │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 5: DECRYPT STORED HASH                                     │
│ • Method: deriveEncryptionKey(salt) + decryptAesGcm()          │
│ • Derive encryption key via PBKDF2                              │
│ • Extract IV from encrypted_hash                                │
│ • Decrypt with AES-256-GCM                                      │
│ • Verify authentication tag                                     │
│ • Output: Original Argon2id hash (64 bytes)                    │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 6: RECOMPUTE PASSWORD HASH                                 │
│ • Method: applyPepper() + argon2idHash()                       │
│ • Apply pepper to login password                                │
│ • Run Argon2id with extracted parameters                        │
│ • Generate 64-byte hash                                         │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 7: CONSTANT-TIME COMPARISON                                │
│ • Method: constantTimeEquals(computed_hash, stored_hash)        │
│ • XOR all byte pairs                                            │
│ • Check if result == 0                                          │
│ • Prevents timing attacks                                       │
│ • Return: true (match) or false (no match)                     │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 8: SECURITY AUDIT LOGGING                                  │
│ • Method: SecurityAuditLogger.log()                             │
│ • Log: timestamp, username, IP, result (success/failure)       │
│ • If failed: increment failure counter → trigger alerts        │
│ • If success: check needsRehash() → upgrade if needed          │
└─────────────────────────────────────────────────────────────────┘
```

### Sensitive Data Encryption Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ INPUT: User email "john.doe@example.com"                        │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: NORMALIZATION                                           │
│ • Method: encryptEmail() → normalize                            │
│ • Operation: lowercase + trim                                   │
│ • Result: "john.doe@example.com"                               │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌──────────────────────┬──────────────────────────────────────────┐
│ PARALLEL PROCESSING  │                                          │
├──────────────────────┴──────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────┐    ┌─────────────────────────┐   │
│  │ PATH A: ENCRYPTION      │    │ PATH B: BLIND INDEX     │   │
│  │                         │    │                         │   │
│  │ • encryptField()        │    │ • createBlindIndex()    │   │
│  │ • AES-256-GCM           │    │ • HMAC-SHA256           │   │
│  │ • Random IV             │    │ • Truncate to 128-bit   │   │
│  │ • Generate tag          │    │ • Base64 encode         │   │
│  │                         │    │                         │   │
│  │ Output:                 │    │ Output:                 │   │
│  │ "ENC$v1$[ciphertext]"   │    │ "Ab12Cd34Ef56..."       │   │
│  └───────────┬─────────────┘    └──────────┬──────────────┘   │
│              │                               │                  │
└──────────────┼───────────────────────────────┼──────────────────┘
               │                               │
               └───────────┬───────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: STORE IN DATABASE                                       │
│ • Column 1: email_encrypted = "ENC$v1$..."                     │
│ • Column 2: email_index = "Ab12Cd34Ef56..."                    │
│ • Allows searching by index without decryption                  │
└─────────────────────────────────────────────────────────────────┘
```

### Data Retrieval and Display Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ QUERY: Search user by email                                     │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: CREATE SEARCH INDEX                                     │
│ • Method: createBlindIndex("search@example.com")               │
│ • Normalize input → HMAC-SHA256 → Truncate → Base64            │
│ • Result: "Xy78Zw..."                                          │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: DATABASE QUERY                                          │
│ • SQL: SELECT * FROM users WHERE email_index = 'Xy78Zw...'     │
│ • Returns: Encrypted records matching the index                 │
│ • No decryption needed for searching                            │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: DECRYPT FOR AUTHORIZED USER                             │
│ • Method: decryptField("ENC$v1$...")                           │
│ • Parse format → Extract ciphertext → Decode Base64            │
│ • Extract IV → AES-256-GCM decrypt → Verify tag                │
│ • Result: "john.doe@example.com"                               │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: MASK FOR DISPLAY                                        │
│ • Method: maskEmail("john.doe@example.com")                    │
│ • Keep first 2 chars + domain                                   │
│ • Replace middle with ***                                       │
│ • Display: "jo***@example.com"                                 │
└─────────────────────────────────────────────────────────────────┘
```

### E2E Encryption Flow (ECIES)

```
┌─────────────────────────────────────────────────────────────────┐
│ SENDER: Wants to send encrypted message to RECIPIENT            │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 1: GENERATE EPHEMERAL KEYPAIR                              │
│ • Method: generateKeyPair()                                     │
│ • Curve: P-384 (ECDH)                                          │
│ • Output: (ephemeral_private, ephemeral_public)                │
│ • Note: Keys are temporary, used only for this message         │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 2: ECDH KEY EXCHANGE                                        │
│ • Method: deriveSharedKey(ephemeral_private, recipient_public) │
│ • Operation: ECDH(our_private, their_public)                   │
│ • Apply HKDF: Extract-Expand with "E2E-AES-KEY"                │
│ • Wipe shared secret from memory                                │
│ • Output: 256-bit AES key                                       │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 3: ENCRYPT MESSAGE                                         │
│ • Method: AES-256-GCM                                           │
│ • Generate random IV (12 bytes)                                 │
│ • Encrypt plaintext with derived key                            │
│ • Add authentication tag (128-bit)                              │
│ • Output: [ciphertext || tag]                                   │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ STEP 4: PACKAGE FOR TRANSMISSION                                │
│ • Combine: [ephemeral_public || IV || ciphertext || tag]       │
│ • Encode to Base64                                              │
│ • Result: "MIGb..." (ready to send)                            │
└─────────────────────────────────┬───────────────────────────────┘
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ RECIPIENT: DECRYPT MESSAGE                                       │
│ • Method: decryptWithPrivateKey()                               │
│ • Decode Base64 → Parse components                              │
│ • Extract ephemeral_public (97 bytes for P-384)                │
│ • ECDH: Derive shared key with own private key                  │
│ • AES-256-GCM: Decrypt with derived key                         │
│ • Verify authentication tag                                     │
│ • Return: Original plaintext message                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Method Category Summary

### Encryption Methods (11)
- `encryptAesGcm()` - Core AES-256-GCM encryption
- `decryptAesGcm()` - Core AES-256-GCM decryption
- `encryptToBase64()` - String encryption
- `decryptFromBase64()` - String decryption
- `encryptField()` - Database field encryption
- `decryptField()` - Database field decryption
- `encryptSearchable()` - Searchable encryption with blind index
- `encryptForRecipient()` - Hybrid E2E encryption (ECIES)
- `decryptWithPrivateKey()` - Hybrid E2E decryption
- `encryptSymmetric()` - Pre-shared key encryption
- `decryptSymmetric()` - Pre-shared key decryption

### Hashing Methods (5)
- `hashPassword()` - Multi-layer password hashing
- `verifyPassword()` - Password verification
- `argon2idHash()` - Argon2id memory-hard hashing
- `hmacSign()` - HMAC-SHA512 signature
- `hmacVerify()` - HMAC verification

### Key Management Methods (7)
- `generateKeyPair()` - ECDH keypair generation
- `deriveKey()` - PBKDF2 key derivation
- `deriveSharedKey()` - ECDH shared secret derivation
- `generateRandomKey()` - Random AES key generation
- `generateSalt()` - Cryptographic salt generation
- `generateSecureToken()` - Random token generation
- `loadOrGenerateKey()` - Key loading/generation

### Data Protection Methods (8)
- `createBlindIndex()` - Searchable encryption index
- `maskEmail()` - Email masking for display
- `maskPhoneNumber()` - Phone masking
- `maskIdNumber()` - ID number masking
- `maskName()` - Name masking
- `mightContainPII()` - PII detection
- `redactPII()` - PII redaction for logs
- `applyPepper()` - Pepper application

### Security Utilities (6)
- `constantTimeEquals()` - Timing attack prevention
- `wipeMemory()` - Secure memory wiping
- `xorBytes()` - XOR operation
- `bytesToHex()` - Hex encoding
- `hexToBytes()` - Hex decoding
- `needsRehash()` - Hash upgrade detection

---

## 🛡️ CIA Triad Implementation

### Confidentiality (Data Privacy)

| Implementation | Method/Class | How It Works |
|----------------|--------------|--------------|
| **Password Protection** | `MultiLayerPasswordVault` | 5-layer encryption: pepper → Argon2id → AES-256-GCM → HMAC → PBKDF2 prevents unauthorized access |
| **Field Encryption** | `SensitiveDataProtector.encryptField()` | AES-256-GCM encrypts emails, phones, IDs before database storage |
| **E2E Encryption** | `E2EEncryption.encryptForRecipient()` | ECDH P-384 + AES-256-GCM ensures only recipient can decrypt |
| **Access Control** | `SecureSessionManager` | Token-based session management limits data access to authorized users |
| **Data Masking** | `SensitiveDataProtector.maskEmail()` | Displays masked data (jo***@example.com) to unauthorized viewers |
| **Memory Protection** | `CryptoCore.wipeMemory()` | Overwrites sensitive data in RAM after use |
| **Logging Redaction** | `SensitiveDataProtector.redactPII()` | Removes PII from logs: [EMAIL REDACTED], [PHONE REDACTED] |

### Integrity (Data Accuracy & Trustworthiness)

| Implementation | Method/Class | How It Works |
|----------------|--------------|--------------|
| **Authentication Tags** | `AES-256-GCM` | 128-bit tag verifies data hasn't been tampered, fails decryption if modified |
| **HMAC Signatures** | `MultiLayerPasswordVault.hmacSign()` | HMAC-SHA512 signs encrypted hashes, detects tampering before decryption |
| **Hash Verification** | `PasswordSecurityUtil.verifyPassword()` | Constant-time comparison prevents timing attacks, ensures password integrity |
| **Blind Index Integrity** | `SensitiveDataProtector.createBlindIndex()` | HMAC-based index ensures search queries match exact data |
| **Digital Signatures** | `E2EEncryption + HMAC` | HMAC-SHA384 in HKDF ensures derived keys haven't been altered |
| **Audit Logging** | `SecurityAuditLogger` | Immutable logs track all security events: login, encryption, access attempts |
| **Version Control** | `ENC$v1$`, `$MLP$v1$` | Format versioning prevents replay attacks with old encryption schemes |
| **AAD Support** | `E2EEncryption.encryptWithAAD()` | Authenticated Associated Data binds metadata (user ID, timestamp) to ciphertext |

#### Integrity Implementation Details

**1. Authentication Tags (AES-GCM)**
```java
// In CryptoCore.encryptAesGcm()
GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);  // 128-bit tag
cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
byte[] ciphertext = cipher.doFinal(plaintext);  // Returns [ciphertext || 128-bit tag]

// Tag verified automatically during decryption
cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
byte[] plaintext = cipher.doFinal(encrypted);  // Throws exception if tag invalid
```
- **What it protects:** Detects any modification to encrypted data (even 1 bit change)
- **When it fails:** Throws `AEADBadTagException` if ciphertext or tag is altered
- **Performance:** Hardware-accelerated, adds <1ms overhead

**2. HMAC Signatures (Multi-Layer Vault)**
```java
// In MultiLayerPasswordVault.hashPassword()
// Layer 4: Sign the encrypted hash
SecretKey hmacKey = deriveHmacKey(salt);
byte[] hmacSignature = hmacSign(encryptedHash, hmacKey);  // 64-byte signature

// In verifyPassword() - FAIL FAST approach
byte[] storedHmac = Arrays.copyOfRange(combined, combined.length - 64, combined.length);
byte[] computedHmac = hmacSign(encryptedHash, hmacKey);
if (!constantTimeEquals(computedHmac, storedHmac)) {
    return false;  // Stop immediately if tampered
}
```
- **What it protects:** Detects tampering BEFORE expensive decryption/hashing
- **Fail-fast:** Rejects invalid data in <1ms, saves ~200ms of computation
- **Attack resistance:** HMAC-SHA512 is quantum-resistant

**3. Constant-Time Comparison**
```java
// In CryptoCore.constantTimeEquals()
private static boolean constantTimeEquals(byte[] a, byte[] b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
        result |= a[i] ^ b[i];  // XOR all bytes
    }
    return result == 0;  // Single final comparison
}
```
- **What it protects:** Prevents timing attacks that measure comparison speed
- **How it works:** Always processes ALL bytes, regardless of where difference occurs
- **Example attack prevented:** Attacker can't guess password byte-by-byte by timing

**4. Hash Chain Audit Logging**
```java
// In SecurityAuditLogger
private static String previousHash = "GENESIS_BLOCK_" + System.currentTimeMillis();

// Each log entry includes hash of previous entry (blockchain-style)
String computeHash(AuditEvent event) {
    String data = event.timestamp + event.eventType + event.username + 
                  event.action + previousHash;  // Include previous hash
    return SHA256(data);
}

// Log format: [timestamp][event][user][action][previous_hash][current_hash]
// Any tampering breaks the chain → easily detected
```
- **What it protects:** Immutable audit trail, detects if logs are modified/deleted
- **How detection works:** If log N is altered, hash chain breaks at log N+1
- **Real-world use:** Same principle as blockchain

**5. Database Audit Logging**
```java
// In LoginAuditLogger.logLoginEvent()
String sql = "INSERT INTO audit_logs (event_type, username, ip_address, " +
             "action, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)";

// Logs stored in database with:
// - Auto-incrementing ID (detects deleted rows)
// - Timestamp (immutable, server-side)
// - Event details (who, what, when, where)
```
- **What it protects:** User activity tracking, compliance requirements
- **Dual logging:** File-based (SecurityAuditLogger) + Database (LoginAuditLogger)
- **Retention:** Database logs kept indefinitely, files rotated daily

**6. Intrusion Detection System**
```java
// In IntrusionDetection
// Tracks and blocks suspicious activity
private static final Map<String, ThreatScore> THREAT_SCORES = new ConcurrentHashMap<>();

void addScore(int points, String indicator) {
    score.addAndGet(points);
    indicators.add(String.format("[%s] %s (+%d)", Instant.now(), indicator, points));
    
    if (score.get() >= THREAT_SCORE_BLOCK_THRESHOLD) {
        blockEntity(identifier, "High threat score: " + score.get());
        triggerAlert(SecurityAlert.CRITICAL, "Entity blocked due to threat score");
    }
}
```
- **What it protects:** Detects brute force, rate limiting violations, SQL injection
- **Threat scoring:** Failed login (+10), SQL injection attempt (+50), XSS (+30)
- **Auto-blocking:** IP blocked for 1 hour when threat score ≥ 100

**7. Format Versioning**
```java
// Password format: $MLP$v1$[salt]$[pepper_id]$[params]$[data]
// Data format: ENC$v1$[ciphertext]

// Version check prevents downgrade attacks
if (!storedHash.startsWith("$MLP$v1$")) {
    // Reject older/unknown formats
    return false;
}
```
- **What it protects:** Prevents replay attacks with old encryption schemes
- **Migration path:** Can upgrade users transparently (check `needsRehash()`)
- **Future-proof:** v2, v3 can coexist during transitions

**8. Rate Limiting**
```java
// In IntrusionDetection.checkLoginAttempt()
RateLimitBucket bucket = IP_LOGIN_BUCKETS.computeIfAbsent(
    ipAddress, k -> new RateLimitBucket(LOGIN_WINDOW, MAX_LOGIN_ATTEMPTS_PER_IP)
);

if (!bucket.tryAcquire()) {
    // Exceeded 10 attempts in 15 minutes
    blockIP(ipAddress, BLOCK_DURATION, "Exceeded login rate limit");
    return false;
}
```
- **What it protects:** Prevents brute force attacks, credential stuffing
- **Limits:** 10 attempts per IP per 15 min, 5 per user per 15 min
- **Sliding window:** Dynamically tracks attempts, not simple counters

### Availability (System Uptime & Accessibility)

| Implementation | Method/Class | How It Works |
|----------------|--------------|--------------|
| **Searchable Encryption** | `SensitiveDataProtector.createBlindIndex()` | Blind indexes allow fast searching without decrypting entire database |
| **Format Detection** | `PasswordSecurityUtil.verifyPassword()` | Auto-detects hash formats (MLP/Argon2id) for backward compatibility |
| **Graceful Degradation** | `MultiLayerPasswordVault.verifyLegacyArgon2()` | Supports old password formats, system remains operational during upgrades |
| **Fast Verification** | `HMAC verification (Layer 4)` | Fail-fast HMAC check rejects tampered data instantly without full decryption |
| **Efficient Algorithms** | `AES-256-GCM` | Hardware-accelerated AES-NI support, processes encryption at GB/s speeds |
| **Session Management** | `SecureSessionManager` | Persistent sessions prevent repeated authentication, reduces login bottlenecks |
| **Parallel Processing** | `Argon2id parallelism=8` | Multi-threaded hashing uses all CPU cores efficiently |
| **Connection Pooling** | `DatabaseConnection` | Maintains connection pool, prevents database connection exhaustion |

### CIA Summary Table

| Security Goal | Primary Protection | Secondary Protection | Detection Mechanism |
|---------------|-------------------|---------------------|---------------------|
| **Confidentiality** | AES-256-GCM encryption | 5-layer password vault | PII detection, masking |
| **Integrity** | HMAC-SHA512 signatures | GCM authentication tags | Constant-time verification |
| **Availability** | Blind index searching | Format auto-detection | Security audit logs |

### CIA in Action: Login Example

```
Login Request: username="john", password="secret123"
│
├─ CONFIDENTIALITY ────────────────────────────────────────
│   • Password transmitted over encrypted channel
│   • Never logged in plaintext (redactPII)
│   • Database stores only encrypted hash
│   • Memory wiped after verification
│
├─ INTEGRITY ──────────────────────────────────────────────
│   • Retrieve stored hash: $MLP$v1$[salt]$...$[enc+hmac]
│   • Verify HMAC first (fail-fast if tampered)
│   • Decrypt hash using AES-256-GCM (verify auth tag)
│   • Recompute: pepper → Argon2id → constant-time compare
│   • Audit log: timestamp, IP, result (success/fail)
│
└─ AVAILABILITY ───────────────────────────────────────────
    • Fast HMAC check rejects invalid data immediately
    • Auto-detect format (supports legacy hashes)
    • Parallel Argon2id processing (8 threads)
    • Session token generated (avoid repeated auth)
    • Connection pool ready for next request
    • Total time: ~200-500ms per login
```

---

**Document Version:** 2.0  
**Last Updated:** February 2, 2026  
**Security Level:** Maximum Protection
