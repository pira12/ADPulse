"""
sysvol_scanner.py
-----------------
Optional SMB-based SYSVOL inspection.

Historically ADPulse was strictly LDAP-only. This module adds the ability to read
the domain SYSVOL share over SMB to detect Group Policy Preferences (GPP) passwords
— the classic "cpassword" weakness (MS14-025). The static AES key used to protect
these values was published by Microsoft, so ANY authenticated user who can read
SYSVOL can decrypt them. Finding them is therefore a high-value, low-privilege check.

Security posture (this module is deliberately conservative):
  * Disabled by default — only runs when [sysvol] enabled = true in config.
  * Strictly READ-ONLY. It opens files for reading and never writes to SYSVOL.
  * Bounded: caps the number of files and per-file size it will read, and only
    looks at *.xml policy files, to avoid resource exhaustion on huge shares.
  * It NEVER writes recovered plaintext passwords into findings or reports. It
    reports the affected username and the fact that the credential is trivially
    recoverable. (Decryption is attempted only to confirm the value is valid GPP
    ciphertext; the plaintext is discarded.)
  * Uses the same credentials already configured for LDAP — no new secrets.
  * Optional dependency: requires the pure-Python 'smbprotocol' package. If it is
    not installed, the scanner degrades gracefully (logs and returns nothing).
"""

import logging
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

# Public AES-256 key Microsoft used for GPP cpassword (disclosed in MS14-025).
_GPP_AES_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)

# Attribute names that may accompany a cpassword, used to identify the account.
_NAME_ATTRS = ("userName", "newName", "accountName", "runAs", "name", "username")

# Safety limits
_MAX_FILES = 5000
_MAX_FILE_BYTES = 1024 * 1024  # 1 MB
_GPP_FILES = (
    "groups.xml", "services.xml", "scheduledtasks.xml",
    "datasources.xml", "printers.xml", "drives.xml",
)


def decrypt_gpp_cpassword(cpassword: str):
    """
    Attempt to decrypt a GPP cpassword to confirm it is valid ciphertext.
    Returns True if it decrypts cleanly, False otherwise. The recovered plaintext
    is intentionally discarded and never returned, so this tool does not persist
    cleartext credentials.

    Requires the optional 'cryptography' package; if unavailable, returns None
    (meaning "could not verify", but the cpassword presence is still reported).
    """
    if not cpassword:
        return False
    try:
        import base64
        import binascii
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except BaseException:
        # Library missing or its native backend is broken — cannot verify.
        return None

    try:
        # Restore base64 padding (GPP strips it).
        pad = len(cpassword) % 4
        if pad:
            cpassword = cpassword + ("=" * (4 - pad))
        blob = base64.b64decode(cpassword)
        cipher = Cipher(algorithms.AES(_GPP_AES_KEY), modes.CBC(b"\x00" * 16))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(blob) + decryptor.finalize()
        # Strip PKCS7 padding then ensure it decodes as UTF-16-LE (GPP encoding).
        if decrypted:
            pad_len = decrypted[-1]
            if 0 < pad_len <= 16:
                decrypted = decrypted[:-pad_len]
            decrypted.decode("utf-16-le")  # raises if not valid plaintext
        return True
    except (ValueError, TypeError, binascii.Error):
        # Genuinely invalid ciphertext (bad base64 / block size / padding).
        return False
    except BaseException:
        # A crypto-backend fault (e.g. a native panic) must never crash a scan.
        # We could not verify the value, but the cpassword is still reported.
        return None


def find_cpasswords(xml_text: str) -> list:
    """
    Parse a GPP XML file and return a list of {"account": str} for every element
    carrying a non-empty cpassword attribute. Plaintext is never included.
    """
    results = []
    if not xml_text or "cpassword" not in xml_text:
        return results
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return results

    for elem in root.iter():
        cpw = elem.attrib.get("cpassword")
        if not cpw:
            continue
        account = "(unknown)"
        for key in _NAME_ATTRS:
            if elem.attrib.get(key):
                account = elem.attrib[key]
                break
        results.append({"account": account, "valid": decrypt_gpp_cpassword(cpw)})
    return results


class SysvolScanner:
    """
    Reads SYSVOL over SMB to find GPP cpassword credentials.

    Use as: SysvolScanner(ldap_cfg).scan() -> list[finding dict]
    Returns [] if disabled, if the SMB library is missing, or on any error.
    """

    def __init__(self, ldap_cfg: dict):
        self.server = ldap_cfg.get("server", "")
        self.domain = ldap_cfg.get("domain", "")
        self.username = (ldap_cfg.get("username") or "").strip()
        self.password = (ldap_cfg.get("password") or "").strip()
        self.timeout = int(ldap_cfg.get("timeout", 30) or 30)

    def scan(self) -> list:
        try:
            import smbclient  # provided by the 'smbprotocol' package
        except Exception:
            logger.warning(
                "SYSVOL scan requested but 'smbprotocol' is not installed. "
                "Install it (pip install smbprotocol) to enable GPP cpassword detection. "
                "Skipping."
            )
            return []

        share = rf"\\{self.server}\SYSVOL"
        affected = []
        files_read = 0

        try:
            if self.username and self.password:
                user = self.username
                if "\\" not in user and "@" not in user and self.domain:
                    user = f"{self.domain}\\{user}"
                smbclient.register_session(
                    self.server, username=user, password=self.password,
                    connection_timeout=self.timeout,
                )
            # Walk the share looking for GPP policy files (read-only).
            for root, _dirs, files in smbclient.walk(share):
                for fname in files:
                    if fname.lower() not in _GPP_FILES:
                        continue
                    if files_read >= _MAX_FILES:
                        logger.warning("SYSVOL scan hit file cap; stopping early.")
                        break
                    full = root.rstrip("\\") + "\\" + fname
                    files_read += 1
                    try:
                        with smbclient.open_file(full, mode="rb") as fh:
                            data = fh.read(_MAX_FILE_BYTES + 1)
                        if len(data) > _MAX_FILE_BYTES:
                            logger.debug(f"Skipping oversized SYSVOL file: {full}")
                            continue
                        text = data.decode("utf-8", errors="ignore")
                        for hit in find_cpasswords(text):
                            affected.append(f"{hit['account']} (in {fname})")
                    except Exception as e:
                        logger.debug(f"Could not read {full}: {e}")
        except Exception as e:
            logger.warning(f"SYSVOL scan failed (read-only): {e}")
            return []
        finally:
            try:
                smbclient.reset_connection_cache()
            except Exception:
                pass

        if not affected:
            logger.info("SYSVOL scan complete: no GPP cpassword credentials found.")
            return []

        return [{
            "finding_id": "GPP-001-CPASSWORD",
            "category": "Password Hygiene",
            "severity": "CRITICAL",
            "title": f"Recoverable GPP Passwords in SYSVOL ({len(affected)})",
            "description": (
                f"{len(affected)} Group Policy Preferences credential(s) with a 'cpassword' "
                "attribute were found in SYSVOL. The AES key protecting these values was "
                "published by Microsoft (MS14-025), so ANY authenticated domain user who can "
                "read SYSVOL can recover the plaintext password. These credentials must be "
                "considered compromised."
            ),
            "affected": affected,
            "details": {"count": len(affected), "files_scanned": files_read},
            "remediation": (
                "1. Immediately rotate the passwords of every affected account.\n"
                "2. Delete the offending GPP XML files from SYSVOL.\n"
                "3. Stop using Group Policy Preferences to set passwords — use LAPS for local "
                "admin passwords and gMSA for service accounts.\n"
                "4. Apply the MS14-025 update to prevent new cpassword values being created."
            ),
        }]
