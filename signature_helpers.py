"""Helper functions for AWS signature calculation shared between main.py and sign_s3.py"""

import base64
import hashlib
import hmac


def calculate_signature_v2(secret_key, bucket, object_key, expiration):
    """Calculate AWS Signature V2

    Args:
        secret_key: AWS secret key
        bucket: S3 bucket name
        object_key: S3 object key/path
        expiration: Unix timestamp for expiration

    Returns:
        Base64-encoded signature string
    """
    string_to_sign = f"GET\n\n\n{expiration}\n/{bucket}/{object_key}"

    signature = hmac.new(
        secret_key.encode('utf-8'),
        string_to_sign.encode('utf-8'),
        hashlib.sha1
    ).digest()

    return base64.b64encode(signature).decode('utf-8')


def calculate_signature_v4(secret_key, datestamp, timestamp, credential_scope, canonical_request, region=''):
    """Calculate AWS Signature V4

    Args:
        secret_key: AWS secret key
        datestamp: Date in YYYYMMDD format
        timestamp: ISO timestamp in YYYYMMDDTHHMMSSZ format
        credential_scope: Credential scope string
        canonical_request: Canonical request string
        region: AWS region (empty string for S3-compatible services)

    Returns:
        Hex-encoded signature string
    """
    # String to sign
    algorithm = 'AWS4-HMAC-SHA256'
    string_to_sign = f"{algorithm}\n{timestamp}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

    # Signing key
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    kDate = sign(('AWS4' + secret_key).encode('utf-8'), datestamp)
    kRegion = sign(kDate, region)
    kService = sign(kRegion, 's3')
    kSigning = sign(kService, 'aws4_request')

    # Signature
    return hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
