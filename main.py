import hashlib
import hmac
import os
import urllib.parse

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse, JSONResponse
from starlette.routing import Route

from sign_s3 import generate_presigned_url_v4

# Configuration
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY", "your_access_key_here")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY", "your_secret_key_here")
ORIGIN_DOMAIN = os.getenv("ORIGIN_DOMAIN", "s3.example.com")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
PORT = int(os.getenv("PORT", "8000"))


class AWSSignatureVerificationMiddleware(BaseHTTPMiddleware):
    """Middleware to verify AWS signatures before processing requests"""

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request, call_next):
        # Parse query parameters
        query_params = parse_query_params(request.url.query)

        # Skip verification for non-signed requests (pass through)
        if 'X-Amz-Signature' not in query_params:
            return await call_next(request)

        # Verify AWS signature
        try:
            if not self.verify_signature(request, query_params):
                return JSONResponse(
                    {"error": "Invalid AWS signature"},
                    status_code=403
                )
        except Exception as e:
            return JSONResponse(
                {"error": f"Signature verification failed: {str(e)}"},
                status_code=400
            )

        # Signature is valid, proceed with request
        return await call_next(request)

    def verify_signature(self, request, query_params):
        """Verify the AWS Signature V4"""

        # Check if access key matches
        credential = query_params.get('X-Amz-Credential', [''])[0]
        if not credential.startswith(AWS_ACCESS_KEY):
            return False

        # Extract signature components
        algorithm = query_params.get('X-Amz-Algorithm', [''])[0]
        if algorithm != 'AWS4-HMAC-SHA256':
            return False

        provided_signature = query_params.get('X-Amz-Signature', [''])[0]
        amz_date = query_params.get('X-Amz-Date', [''])[0]
        signed_headers = query_params.get('X-Amz-SignedHeaders', ['host'])[0]

        if not all([provided_signature, amz_date]):
            return False

        # Calculate expected signature with the incoming host
        incoming_host = request.headers.get('host', '')
        expected_signature = self.calculate_signature(
            method=request.method,
            host=incoming_host,
            path=request.url.path,
            query_params=query_params,
            headers=dict(request.headers),
            amz_date=amz_date,
            signed_headers=signed_headers
        )

        # Compare signatures
        return hmac.compare_digest(provided_signature, expected_signature)

    def calculate_signature(self, method, host, path, query_params, headers, amz_date, signed_headers):
        """Calculate AWS Signature V4"""

        date_stamp = amz_date[:8]
        credential_scope = f"{date_stamp}/{AWS_REGION}/s3/aws4_request"

        # Create canonical query string (exclude signature)
        canonical_querystring_parts = []
        for key, values in sorted(query_params.items()):
            if key == 'X-Amz-Signature':
                continue
            for value in values:
                canonical_querystring_parts.append(
                    f"{urllib.parse.quote(key, safe='')}={urllib.parse.quote(str(value), safe='')}"
                )
        canonical_querystring = "&".join(canonical_querystring_parts)

        # Create canonical headers
        signed_headers_list = signed_headers.split(';')
        canonical_headers = ""
        for header in sorted(signed_headers_list):
            if header == 'host':
                canonical_headers += f"host:{host}\n"
            elif header.lower() in headers:
                canonical_headers += f"{header}:{headers[header.lower()].strip()}\n"

        # Create canonical request
        payload_hash = "UNSIGNED-PAYLOAD"
        canonical_request = f"{method}\n{path}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        # String to sign
        algorithm = 'AWS4-HMAC-SHA256'
        string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

        # Calculate signature
        def sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        kDate = sign(('AWS4' + AWS_SECRET_KEY).encode('utf-8'), date_stamp)
        kRegion = sign(kDate, AWS_REGION)
        kService = sign(kRegion, 's3')
        kSigning = sign(kService, 'aws4_request')

        signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        return signature


def parse_query_params(query_string):
    """Parse query string into dict with lists of values"""
    params = {}
    if query_string:
        for param in query_string.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                key = urllib.parse.unquote(key)
                value = urllib.parse.unquote(value)
                if key in params:
                    params[key].append(value)
                else:
                    params[key] = [value]
    return params


def validate_and_resign_url(request):
    """Validate original signature and create new signature for origin domain"""

    # Parse query parameters
    query_params = parse_query_params(request.url.query)

    # Check if this is a signed request
    if 'X-Amz-Signature' not in query_params:
        return request.url.query  # Not a signed request, pass through

    # Verify the access key matches
    credential = query_params.get('X-Amz-Credential', [''])[0]
    if not credential.startswith(AWS_ACCESS_KEY):
        raise ValueError("Access key mismatch")

    # Extract bucket and object from path
    path_parts = request.url.path.strip('/').split('/', 1)
    if len(path_parts) < 2:
        raise ValueError("Invalid S3 path")

    bucket, object_key = path_parts[0], path_parts[1]

    # Extract expires from original request
    expires_str = query_params.get('X-Amz-Expires', ['3600'])[0]
    expires_in = int(expires_str)

    # Generate new presigned URL using the imported function
    new_url = generate_presigned_url_v4(
        endpoint=f"https://{ORIGIN_DOMAIN}",
        access_key=AWS_ACCESS_KEY,
        secret_key=AWS_SECRET_KEY,
        bucket=bucket,
        object_key=object_key,
        expires_in=expires_in,
        region=AWS_REGION
    )

    # Extract just the query string from the new URL
    parsed_url = urllib.parse.urlparse(new_url)
    return parsed_url.query


async def proxy_handler(request):
    """Handle proxy requests"""
    try:
        # Validate and re-sign the URL
        new_query_string = validate_and_resign_url(request)

        # Build target URL
        target_url = f"https://{ORIGIN_DOMAIN}{request.url.path}"
        if new_query_string:
            target_url += f"?{new_query_string}"

        # Forward request to origin
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers={k: v for k, v in request.headers.items()
                         if k.lower() not in ['host', 'content-length']},
                content=await request.body() if request.method in ['POST', 'PUT', 'PATCH'] else None
            )

            # Stream response back
            def generate():
                for chunk in response.iter_bytes():
                    yield chunk

            return StreamingResponse(
                generate(),
                status_code=response.status_code,
                headers=dict(response.headers)
            )

    except Exception as e:
        from starlette.responses import JSONResponse
        return JSONResponse(
            {"error": f"Proxy error: {str(e)}"},
            status_code=400
        )


async def health_check(request):
    """Check if origin server is responding"""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.head(f"https://{ORIGIN_DOMAIN}")
            if 200 <= response.status_code < 300:
                return JSONResponse({"status": "ok"}, status_code=200)
    except Exception:
        pass

    return JSONResponse({"status": "nok"}, status_code=450)


# Routes
routes = [
    Route("/healthz", health_check, methods=["GET"]),
    Route("/{path:path}", proxy_handler, methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
]

# Create Starlette app with middleware
middleware = [
    Middleware(AWSSignatureVerificationMiddleware)
]

app = Starlette(routes=routes, middleware=middleware)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
