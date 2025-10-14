# -*- coding: utf-8 -*-
# @Time: 2024/7/28 19:55
# @FileName: event.py
# @Software: PyCharm

import aiohttp
import json
import tempfile
import time
import xml.etree.ElementTree as ET
from loguru import logger
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
import os
import uuid

# Define the URL to fetch banned serial numbers
BANNED_SERIALS_URL = "https://raw.githubusercontent.com/daboynb/autojson/refs/heads/main/banned.txt"

# Path to the leaks.txt file
LEAKS_FILE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "leaks.txt")

async def fetch_banned_serials():
    """
    Fetches the list of banned serial numbers from a remote URL.

    Returns:
        list of str: List containing banned serial numbers.

    Raises:
        Exception: If the HTTP request fails or the response is invalid.
    """
    async with aiohttp.ClientSession() as session:
        async with session.get(BANNED_SERIALS_URL) as response:
            if response.status != 200:
                raise Exception(f"Error fetching banned serials: {response.status}")
            text = await response.text()
            # Split the text by lines and remove any empty lines
            banned_serials = [line.strip().lower() for line in text.splitlines() if line.strip()]
            return banned_serials

def load_leaked_serials():
    """
    Loads the list of leaked serial numbers from the leaks.txt file.

    Returns:
        list of str: List containing leaked serial numbers.

    Raises:
        Exception: If the file cannot be read or is invalid.
    """
    try:
        with open(LEAKS_FILE_PATH, 'r', encoding='utf-8') as file:
            # Split the text by lines and remove any empty lines
            leaked_serials = [line.strip().lower() for line in file.readlines() if line.strip()]
            return leaked_serials
    except Exception as e:
        logger.error(f"Failed to load leaked serials: {e}")
        return []

async def load_from_url():
    """
    Fetches the revocation status from Google's attestation status URL.

    Returns:
        dict: JSON response containing revocation status information.

    Raises:
        Exception: If the HTTP request fails or returns a non-200 status code.
    """
    url = "https://android.googleapis.com/attestation/status"

    timestamp = int(time.time())
    headers = {
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }

    params = {
        "ts": timestamp
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=params) as response:
            if response.status != 200:
                raise Exception(f"Error fetching data: {response.status}")
            return await response.json()

def parse_number_of_certificates(xml_file):
    """
    Parses the XML file to find all occurrences of <NumberOfCertificates>.

    Args:
        xml_file (str): Path to the XML file.

    Returns:
        list of int: List containing the number of certificates specified in each <NumberOfCertificates> tag.

    Raises:
        Exception: If no <NumberOfCertificates> tags are found in the XML.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Find all occurrences of <NumberOfCertificates>
    certificates_counts = root.findall('.//NumberOfCertificates')

    if certificates_counts:
        # Parse each number and store in a list
        counts = [int(certificate.text.strip()) for certificate in certificates_counts]
        return counts
    else:
        raise Exception('No NumberOfCertificates found.')

def parse_certificates(xml_file, pem_number):
    """
    Extracts PEM-formatted certificates from the XML file up to the specified number.

    Args:
        xml_file (str): Path to the XML file containing certificate information.
        pem_number (int): The number of PEM certificates to extract.

    Returns:
        list of str: Extracted PEM certificates in original order.

    Raises:
        Exception: If no PEM certificates are found in the XML.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    pem_certificates = []

    for keybox in root.findall('.//Keybox'):
        for key in keybox.findall('Key'):
            for certificate in key.findall('.//Certificate[@format="pem"]'):
                pem_certificates.append(certificate.text.strip())
                if len(pem_certificates) == pem_number:
                    break
            if len(pem_certificates) == pem_number:
                break
        if len(pem_certificates) == pem_number:
            break

    if pem_certificates:
        return pem_certificates  # Maintain original order (leaf to root)
    else:
        raise Exception("No Certificate found.")

def load_public_key_from_file(file_path):
    """
    Loads a public key from a PEM-formatted file.

    Args:
        file_path (str): Path to the PEM file containing the public key.

    Returns:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey or
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey:
            The loaded public key.
    """
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def compare_keys(public_key1, public_key2):
    """
    Compares two public keys to determine if they are identical.

    Args:
        public_key1: First public key.
        public_key2: Second public key.

    Returns:
        bool: True if the public keys are identical, False otherwise.
    """
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

async def keybox_check(bot, message, document):
    """
    Checks the validity and integrity of a keybox provided in an XML document.

    This function performs the following steps:
    1. Downloads the XML document containing the keybox.
    2. Parses the number of certificates and extracts the PEM-formatted certificates.
    3. Loads and verifies each certificate.
    4. Checks for banned serial numbers.
    5. Verifies the certificate chain and signature.
    6. Checks against the revocation list.
    7. Determines the type of root certificate.
    8. Validates overall keychain integrity.
    9. Checks if the serial number is in the leaks.txt file.

    Args:
        bot: The bot instance used to interact with the messaging platform.
        message: The incoming message containing the keybox document.
        document: The document object representing the keybox file.

    Returns:
        None: Sends a reply to the user with the keybox verification results.
    """
    reply = ""

    # Fetch the list of banned serial numbers
    try:
        banned_serials = await fetch_banned_serials()
        logger.info(f"Fetched {len(banned_serials)} banned serial numbers.")
    except Exception as e:
        logger.error(f"Failed to fetch banned serials: {e}")
        await bot.reply_to(message, "Failed to load the list of banned serial numbers.")
        return
        
    # Load the list of leaked serial numbers
    try:
        leaked_serials = load_leaked_serials()
        logger.info(f"Loaded {len(leaked_serials)} leaked serial numbers.")
    except Exception as e:
        logger.error(f"Failed to load leaked serials: {e}")
        leaked_serials = []

    # Download the file from the provided document
    try:
        file_info = await bot.get_file(document.file_id)
        downloaded_file = await bot.download_file(file_info.file_path)
    except Exception as e:
        logger.error(f"Failed to download the document: {e}")
        await bot.reply_to(message, "Failed to download the keybox document.")
        return

    with tempfile.NamedTemporaryFile(delete=True) as temp_file:
        temp_file.write(downloaded_file)
        temp_file.flush()
        try:
            pem_numbers = parse_number_of_certificates(temp_file.name)
            # Use the maximum value from the list of certificate counts
            max_pem_number = max(pem_numbers)
            if max_pem_number < 3:
                reply += "\n❌ Insufficient certificates in the keychain. A minimum of 3 certificates is required."
            pem_certificates = parse_certificates(temp_file.name, max_pem_number)
        except Exception as e:
            logger.error(f"[Keybox Check][message.chat.id]: {e}")
            await bot.reply_to(message, str(e))
            return

    certificates = []
    try:
        for pem_cert in pem_certificates:
            certificate = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
            certificates.append(certificate)
    except Exception as e:
        logger.error(f"[Keybox Check][message.chat.id]: {e}")
        await bot.reply_to(message, str(e))
        return

    reply = ""
    revoked_certificates = []

    # Initialize the nearest expiration date
    nearest_expiration_date = None

    # Flag to track if any certificate is expired
    any_certificate_expired = False

    # Flag to track if any certificate has a banned serial in the subject
    has_banned_serial = False
    
    # Flag to track if any certificate has a leaked serial
    has_leaked_serial = False

    # Fetch the revocation list once to avoid multiple network calls
    try:
        status_json = await load_from_url()
    except Exception:
        logger.error("Failed to fetch Google's revoked keybox list")
        try:
            with open("res/json/status.json", 'r', encoding='utf-8') as file:
                status_json = json.load(file)
                reply += "\n⚠️ Using local revoked keybox list"
        except Exception as e:
            logger.error(f"Failed to load local revoked keybox list: {e}")
            await bot.reply_to(message, "Failed to load revocation list.")
            return

    # Define the desired date format
    DATE_FORMAT = "%d/%m/%Y"

    # Reverse the order of certificates for display purposes
    for idx, certificate in enumerate(reversed(certificates), 1):
        # Adjust indexing since we're reversing the list
        actual_idx = len(certificates) - idx + 1
        serial_number = certificate.serial_number
        serial_number_string = hex(serial_number)[2:].lower()
        reply += f"\n\n🔐 Certificate {actual_idx} Serial number: `{serial_number_string}`"
        
        # Extract the serialNumber from the subject
        subject_serial_number = None
        for attr in certificate.subject:
            if attr.oid._name == 'serialNumber':
                subject_serial_number = attr.value.lower()
                break
        
        if subject_serial_number:
            reply += f"\nℹ️ *Subject Serial Number:* `{subject_serial_number}`"
            if subject_serial_number in banned_serials:
                reply += "\n❌ This subject serial number is banned."
                has_banned_serial = True
                logger.warning(f"Subject serial number {subject_serial_number} is banned.")
        else:
            reply += "\nℹ️ *Subject Serial Number:* `Not Found`"
        
        # Verify the certificate's validity period
        not_valid_before = certificate.not_valid_before
        not_valid_after = certificate.not_valid_after
        current_time = datetime.utcnow()
        is_valid = not_valid_before <= current_time <= not_valid_after
        
        # Format the validity dates
        formatted_not_valid_before = not_valid_before.strftime(DATE_FORMAT)
        formatted_not_valid_after = not_valid_after.strftime(DATE_FORMAT)
        
        # Add the expiration dates to the reply
        reply += f"\n📅 *Valid from:* `{formatted_not_valid_before}` *to:* `{formatted_not_valid_after}`"
        
        if is_valid:
            reply += "\n✅ Certificate within validity period"
        elif current_time > not_valid_after:
            reply += "\n❌ Expired certificate"
            any_certificate_expired = True
        else:
            reply += "\n❌ Invalid certificate"
        
        # Track the nearest expiration date among all certificates
        if nearest_expiration_date is None or not_valid_after < nearest_expiration_date:
            nearest_expiration_date = not_valid_after

        # Check if the certificate's serial number is banned
        if serial_number_string in banned_serials:
            reply += "\n❌ This serial number is banned. 🔴 This key box *can't be used* for strong integrity"
            has_banned_serial = True
            logger.warning(f"Certificate serial number {serial_number_string} is banned.")
        
        # Check if the certificate's serial number is in the leaks.txt file
        if serial_number_string in leaked_serials:
            reply += "\n⚠️ Leak detected: the keybox can be soft banned"
            has_leaked_serial = True
            logger.warning(f"Certificate serial number {serial_number_string} is in leaks.txt.")
        
        # Check the revocation status for the current certificate
        status = status_json['entries'].get(serial_number_string, None)
        if status is None:
            reply += "\n✅ Serial number not found in Google's revoked keybox list"
        else:
            reply += f"\n❌ Serial number found in Google's revoked keybox list\n🔍 *Reason:* `{status['reason']}`"
            revoked_certificates.append(serial_number_string)

    # Authenticate the certificate chain (Keychain)
    flag = True
    for i in range(len(certificates) - 1):
        son_certificate = certificates[i]
        father_certificate = certificates[i + 1]

        if son_certificate.issuer != father_certificate.subject:
            flag = False
            logger.error(f"Certificate issuer does not match the subject of the next certificate. Certificate {i+1} and {i+2}.")
            break
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()
        try:
            if signature_algorithm in ['sha256WithRSAEncryption', 'sha1WithRSAEncryption', 'sha384WithRSAEncryption',
                                       'sha512WithRSAEncryption']:
                hash_algorithm = {
                    'sha256WithRSAEncryption': hashes.SHA256(),
                    'sha1WithRSAEncryption': hashes.SHA1(),
                    'sha384WithRSAEncryption': hashes.SHA384(),
                    'sha512WithRSAEncryption': hashes.SHA512()
                }[signature_algorithm]
                padding_algorithm = padding.PKCS1v15()
                public_key.verify(signature, tbs_certificate, padding_algorithm, hash_algorithm)
            elif signature_algorithm in ['ecdsa-with-SHA256', 'ecdsa-with-SHA1', 'ecdsa-with-SHA384',
                                         'ecdsa-with-SHA512']:
                hash_algorithm = {
                    'ecdsa-with-SHA256': hashes.SHA256(),
                    'ecdsa-with-SHA1': hashes.SHA1(),
                    'ecdsa-with-SHA384': hashes.SHA384(),
                    'ecdsa-with-SHA512': hashes.SHA512()
                }[signature_algorithm]
                padding_algorithm = ec.ECDSA(hash_algorithm)
                public_key.verify(signature, tbs_certificate, padding_algorithm)
            else:
                raise ValueError("Unsupported signature algorithms")
        except Exception as e:
            logger.error(f"Signature verification failed between certificates {i+1} and {i+2}: {e}")
            flag = False
            break
    if flag:
        reply += "\n✅ Valid keychain"
    else:
        reply += "\n❌ Invalid keychain"

    # Validate the Root Certificate by comparing it with known root certificates
    root_certificate = certificates[-1]
    root_public_key = root_certificate.public_key()
    google_public_key = load_public_key_from_file("res/pem/google.pem")
    aosp_ec_public_key = load_public_key_from_file("res/pem/aosp_ec.pem")
    aosp_rsa_public_key = load_public_key_from_file("res/pem/aosp_rsa.pem")
    knox_public_key = load_public_key_from_file("res/pem/knox.pem")
    certificate_type = None
    if compare_keys(root_public_key, google_public_key):
        reply += "\n✅ Google hardware attestation root certificate"
        certificate_type = "hardware"
    elif compare_keys(root_public_key, aosp_ec_public_key):
        reply += "\n🟡 AOSP software attestation root certificate (EC)"
        certificate_type = "software"
    elif compare_keys(root_public_key, aosp_rsa_public_key):
        reply += "\n🟡 AOSP software attestation root certificate (RSA)"
        certificate_type = "software"
    elif compare_keys(root_public_key, knox_public_key):
        reply += "\n✅ Samsung Knox attestation root certificate"
        certificate_type = "knox"
    else:
        # If any certificate is expired, indicate that the root certificate is unknown due to expiration
        if any_certificate_expired:
            reply += "\n❌ Unknown root certificate due to expiration of a certificate"
        else:
            reply += "\n❌ Unknown root certificate"

    # Define individual conditions for keychain validity
    is_within_validity = all(cert.not_valid_before <= datetime.utcnow() <= cert.not_valid_after for cert in certificates)
    is_keychain_valid = flag
    is_correct_root = certificate_type in ["hardware", "knox"]
    is_not_revoked = not revoked_certificates
    is_not_banned = not has_banned_serial
    is_not_leaked = not has_leaked_serial  

    # Determine if the keychain is valid based on all conditions
    is_valid_keychain = (
        len(certificates) >= 3 and
        is_within_validity and 
        is_keychain_valid and
        is_not_revoked and
        is_correct_root and
        is_not_banned and
        is_not_leaked
    )

    # --- Begin: Special serial check ---
    special_serial = "f92009e853b6b045"
    cert_count = len(certificates)
    allowed_index = 2 if cert_count == 3 else 3 if cert_count > 3 else None  # 0-based index

    special_serial_violation = False
    for idx, cert in enumerate(certificates):
        cert_serial = hex(cert.serial_number)[2:].lower()
        # Check subject serial number
        subject_serial = None
        for attr in cert.subject:
            if attr.oid._name == 'serialNumber':
                subject_serial = attr.value.lower()
                break
        # If either matches and not at allowed index, or appears more than once
        if (cert_serial == special_serial or subject_serial == special_serial):
            if allowed_index is None or idx != allowed_index:
                special_serial_violation = True
                break

    # Also ensure it appears at most once at the allowed index
    count_at_allowed = 0
    if allowed_index is not None:
        cert = certificates[allowed_index]
        cert_serial = hex(cert.serial_number)[2:].lower()
        subject_serial = None
        for attr in cert.subject:
            if attr.oid._name == 'serialNumber':
                subject_serial = attr.value.lower()
                break
        if cert_serial == special_serial or subject_serial == special_serial:
            count_at_allowed = 1
    total_count = sum(
        1 for cert in certificates
        if hex(cert.serial_number)[2:].lower() == special_serial or
           any(attr.oid._name == 'serialNumber' and attr.value.lower() == special_serial for attr in cert.subject)
    )
    if total_count > 1:
        special_serial_violation = True

    if special_serial_violation:
        reply += "\n❌ Serial f92009e853b6b045 is only allowed on certificate 3 or 4 if more than 3."
        if has_leaked_serial and not has_banned_serial and is_not_revoked:
            reply += "\n🟡 Since this keybox was in a leak it can be soft banned and if yes you will get only device integrity"
        else:
            reply += "\n🔴 This key box *can't be used* for strong integrity"
        is_valid_keychain = False
    # --- End: Special serial check ---

    # Add the expiration date after all checks
    if nearest_expiration_date:
        current_time = datetime.utcnow()
        if nearest_expiration_date < current_time:
            # Keybox has expired
            formatted_nearest_expiration_date = nearest_expiration_date.strftime(DATE_FORMAT)
            reply += f"\n\n⏳ *Keybox expired on:* `{formatted_nearest_expiration_date}`"
        else:
            formatted_nearest_expiration_date = nearest_expiration_date.strftime(DATE_FORMAT)
            reply += f"\n\n⏳ *Keybox will expire on:* `{formatted_nearest_expiration_date}`"
    else:
        reply += "\n\n⚠️ Unable to determine keybox expiration date."

    reply += "\n\n"
    if is_valid_keychain:
        reply += (
            "\n🟢 This key box *can be used* for strong integrity."
            "\n\nSometimes Google bans a keybox without revoking it, so for now no one can detect that ban. This is a reminder: this bot fetches the Google revocation list but can't know if a keybox is banned, so sometimes false positives can happen."
            "\n\nI have also created a ban list of known keyboxes here: https://raw.githubusercontent.com/daboynb/autojson/refs/heads/main/banned.txt"
            "\nThanks to @antezero, it is almost always up to date, but this method can still fail because it is based on community reports."

        )
    else:
        if has_leaked_serial and not has_banned_serial and is_not_revoked:
            reply += "\n🟡 Since this keybox was in a leak it can be soft banned and if yes you will get only device integrity"
        else:
            reply += "\n🔴 This key box *can't be used* for strong integrity"

    await bot.reply_to(message, reply, parse_mode='Markdown')
