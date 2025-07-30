# Obsidian Vault Encrypt Plugin
Transform your vault into an unrecognizable collection of encrypted files that provides security and anonymity while maintaining seamless user experience.

---

**CAUTION**
1. _Backup the Vault_ - before running the plugin make a backup to save your data.
2. _Remember your Password_ - Without the password used for encryption you cannot decrypt the files.
3. _Early Development_ - This plugin is in early development and testing, remember to backup and if any you have any issues create an issue on this Github.

---

### Obsidian Vault Encryption Installation & Use
Manual Installation: Copy over main.js and manifest.json (from Releases) to your vault in this location: `VaultFolder/.obsidian/plugins/cryptsidian/`.

Git Clone: `git clone` this repository into `VaultFolder/.obsidian/plugins/cryptsidian` and `npm install` and `npm run dev`.

**Use:** Click the lock icon. To encrypt, select the encrypt modal and enter your password. To decrypt, select the decrypt modal and enter the same password. 

Files remain encrypted (or decrypted) after the Obsidian app closes.

---

### Usage Guide
#### Basic Operations
Manual Encryption/Decryption

Encrypt Vault: Click the lock icon in the ribbon or use Command Palette (Ctrl/Cmd + P → "Encrypt entire vault")
Enter Password: Use a strong, memorable password (minimum 8 characters recommended)
Decryption: Use the same methods with your master password

#### Security Configuration
##### Encryption Strength

- Standard Security: 100,000 PBKDF2 iterations (default)
- High Security: 250,000 iterations (slower but more secure)
- Maximum Security: 500,000 iterations (recommended for sensitive data)

##### Password Guidelines

- Recommended Minimum Length: 12+ characters
- Composition: Mix of uppercase, lowercase, numbers, and symbols
- Uniqueness: Use a password manager for unique, strong passwords
- Storage: Never store the master password in plain text

---

### Usability
This plugin has not gone through an security audit and should not be relied upon for critical security applications.

Future changes to the Obsidian API may break this plugin. Forward compatibility is not guaranteed.

---

### Security Features
**Military-Grade Encryption**
- AES-256-GCM: NSA Suite B approved encryption algorithm
- PBKDF2-SHA256: 100,000+ iterations for key derivation (configurable 50k-500k)
- HKDF: High-performance key derivation for file-level encryption

**Maximum Anonymity**
- Complete filename anonymization: Original names replaced with random identifiers
- Structural obliteration: All folders completely removed during encryption
- Size obfuscation: Files padded to standard sizes to hide original content length

---

⚠️ Important Security Notice: This plugin provides strong encryption, but no security tool is perfect. Always maintain secure backups of important data and use strong, unique passwords. The developers are not responsible for data loss due to forgotten passwords or technical failures.

