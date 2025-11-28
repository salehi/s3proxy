import argparse
import hashlib
from datetime import datetime, timedelta
from urllib.parse import quote, urlencode

from signature_helpers import calculate_signature_v2, calculate_signature_v4


def generate_presigned_url_v2(endpoint, access_key, secret_key, bucket, object_key, expires_in, scheme='https'):
    """AWS Signature Version 2"""
    if not endpoint.startswith('http'):
        endpoint = f'{scheme}://{endpoint}'

    expiration = int((datetime.utcnow() + timedelta(seconds=expires_in)).timestamp())
    signature_b64 = calculate_signature_v2(secret_key, bucket, object_key, expiration)

    url = f"{endpoint}/{bucket}/{quote(object_key, safe='/')}"
    params = {
        'AWSAccessKeyId': access_key,
        'Expires': str(expiration),
        'Signature': signature_b64
    }

    return f"{url}?{urlencode(params)}"


def generate_presigned_url_v4(endpoint, access_key, secret_key, bucket, object_key, expires_in, region='us-east-1',
                              scheme='https'):
    """AWS Signature Version 4"""
    if not endpoint.startswith('http'):
        endpoint = f'{scheme}://{endpoint}'

    # Parse endpoint for host
    from urllib.parse import urlparse
    parsed = urlparse(endpoint)
    host = parsed.netloc

    # Timestamps
    now = datetime.utcnow()
    datestamp = now.strftime('%Y%m%d')
    timestamp = now.strftime('%Y%m%dT%H%M%SZ')

    # Credential scope
    credential_scope = f"{datestamp}/{region}/s3/aws4_request"

    # Query parameters
    params = {
        'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
        'X-Amz-Credential': f"{access_key}/{credential_scope}",
        'X-Amz-Date': timestamp,
        'X-Amz-Expires': str(expires_in),
        'X-Amz-SignedHeaders': 'host'
    }

    # Canonical request
    canonical_uri = f"/{bucket}/{object_key}"
    canonical_querystring = urlencode(sorted(params.items()))
    canonical_headers = f"host:{host}\n"
    signed_headers = 'host'
    payload_hash = 'UNSIGNED-PAYLOAD'

    canonical_request = f"GET\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    # Calculate signature using helper
    signature = calculate_signature_v4(secret_key, datestamp, timestamp, credential_scope, canonical_request, region)

    # Final URL
    params['X-Amz-Signature'] = signature
    url = f"{endpoint}/{bucket}/{quote(object_key, safe='/')}"

    return f"{url}?{urlencode(sorted(params.items()))}"


def main():
    parser = argparse.ArgumentParser(description='Generate MinIO/S3 presigned URLs')
    parser.add_argument('endpoint', help='MinIO/S3 endpoint (e.g., minio.example.com:9000)')
    parser.add_argument('access_key', help='Access key')
    parser.add_argument('secret_key', help='Secret key')
    parser.add_argument('bucket', help='Bucket name')
    parser.add_argument('object_key', help='Object key/path')
    parser.add_argument('--expires', '-e', type=int, default=3600, help='Expiration time in seconds (default: 3600)')
    parser.add_argument('--version', '-v', choices=['2', '4'], default='2', help='Signature version (default: 2)')
    parser.add_argument('--region', '-r', default='us-east-1', help='AWS region for v4 (default: us-east-1)')

    args = parser.parse_args()

    if args.version == '2':
        url = generate_presigned_url_v2(
            args.endpoint, args.access_key, args.secret_key,
            args.bucket, args.object_key, args.expires
        )
    elif args.version == '4':
        url = generate_presigned_url_v4(
            args.endpoint, args.access_key, args.secret_key,
            args.bucket, args.object_key, args.expires, args.region
        )

    print(url)


if __name__ == "__main__":
    main()
