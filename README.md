# S3 URL Re-signing Proxy

[![Docker Hub](https://img.shields.io/docker/pulls/s4l3h1/s3proxy)](https://hub.docker.com/r/s4l3h1/s3proxy)
[![GitHub](https://img.shields.io/github/stars/salehi/s3proxy?style=social)](https://github.com/salehi/s3proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Starlette-based proxy service that enables you to serve your custom S3 service under a different domain while maintaining AWS Signature V4 compatibility.

## Problem

When you have a custom S3 service running on `s3.example.com` and want to serve it under `s3.mydomain.com`, AWS Signature V4 authentication breaks because the signature includes the host header in its calculation. Simply proxying requests fails because:

- DNS CNAME causes clients to sign URLs for `s3.mydomain.com` but the origin server expects `s3.example.com`
- Reverse proxy with host header rewriting still has signatures calculated for the wrong domain
- Switching between multiple S3 backends requires clients to manage different credentials for each backend

## Solution

This proxy provides a dual-credential system that:

1. **Client Authentication**: Validates requests using client-facing credentials (shared across all backends)
2. **Origin Re-signing**: Re-signs URLs with backend-specific credentials before forwarding
3. **Load Balancing**: Distributes traffic across multiple S3 backends with automatic health checks
4. **Transparent Failover**: Removes unhealthy backends from rotation automatically

This allows clients to use a single set of credentials while the proxy manages multiple S3 backends transparently.

## Features

- ✅ Dual credential system: separate client and origin credentials
- ✅ AWS Signature V4 re-signing on-the-fly
- ✅ HAProxy load balancing with health checks across multiple S3 backends
- ✅ Automatic backend failover based on origin health
- ✅ Support for all HTTP methods (GET, POST, PUT, DELETE, HEAD)
- ✅ Streaming responses for efficient memory usage
- ✅ Environment variable configuration
- ✅ Health check endpoint (`/healthz`)
- ✅ Error handling for invalid signatures
- ✅ Preserves all original headers and request body

## Installation

### Using Docker (Recommended)

```bash
# Pull from Docker Hub
docker pull s4l3h1/s3proxy:latest

# Run directly
docker run -p 8000:8000 \
  -e AWS_ACCESS_KEY="your_key" \
  -e AWS_SECRET_KEY="your_secret" \
  -e ORIGIN_DOMAIN="s3.example.com" \
  s4l3h1/s3proxy:latest
```

### From Source

```bash
# Clone the repository
git clone https://github.com/salehi/s3proxy.git
cd s3proxy

# Install dependencies
pip install -r requirements.txt
```

## Configuration

### Environment Variables

#### Client-Facing Credentials (Shared)
| Variable | Description | Default |
|----------|-------------|---------|
| `CLIENT_ACCESS_KEY` | Access key clients use to sign requests | `your_client_access_key_here` |
| `CLIENT_SECRET_KEY` | Secret key clients use to sign requests | `your_client_secret_key_here` |

#### Origin Credentials (Backend-Specific)
| Variable | Description | Default |
|----------|-------------|---------|
| `ORIGIN_ACCESS_KEY` | S3 backend access key | `your_origin_access_key_here` |
| `ORIGIN_SECRET_KEY` | S3 backend secret key | `your_origin_secret_key_here` |
| `ORIGIN_DOMAIN` | S3 backend domain | `s3.example.com` |

#### General Settings
| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region | `us-east-1` |
| `PORT` | Server port | `8000` |

## Usage

### Single Backend Deployment

#### Set Environment Variables

```bash
export CLIENT_ACCESS_KEY="your_client_access_key"
export CLIENT_SECRET_KEY="your_client_secret_key"
export ORIGIN_ACCESS_KEY="backend_access_key"
export ORIGIN_SECRET_KEY="backend_secret_key"
export ORIGIN_DOMAIN="s3.example.com"
export AWS_REGION="us-east-1"
export PORT="8000"

python main.py
```

#### Docker Single Instance

```bash
docker run -p 8000:8000 \
  -e CLIENT_ACCESS_KEY="your_client_key" \
  -e CLIENT_SECRET_KEY="your_client_secret" \
  -e ORIGIN_ACCESS_KEY="backend_key" \
  -e ORIGIN_SECRET_KEY="backend_secret" \
  -e ORIGIN_DOMAIN="s3.example.com" \
  s4l3h1/s3proxy:latest
```

### Multi-Backend Deployment with HAProxy (Recommended)

For production deployments with multiple S3 backends and automatic failover:

#### 1. Create `.env` file

```bash
# Client-facing credentials (shared across all backends)
CLIENT_ACCESS_KEY=your_shared_client_access_key
CLIENT_SECRET_KEY=your_shared_client_secret_key

# Server A credentials
SERVERA_ACCESS_KEY=backend_a_access_key
SERVERA_SECRET_KEY=backend_a_secret_key
SERVERA_ENDPOINT=s3.backend-a.com

# Server B credentials
SERVERB_ACCESS_KEY=backend_b_access_key
SERVERB_SECRET_KEY=backend_b_secret_key
SERVERB_ENDPOINT=s3.backend-b.com
```

#### 2. Create `docker-compose.yml`

```yaml
version: '3.8'

services:
  s3-proxy-serverA:
    image: s4l3h1/s3proxy:latest
    ports:
      - "8001:8000"
    environment:
      - CLIENT_ACCESS_KEY=${CLIENT_ACCESS_KEY}
      - CLIENT_SECRET_KEY=${CLIENT_SECRET_KEY}
      - ORIGIN_ACCESS_KEY=${SERVERA_ACCESS_KEY}
      - ORIGIN_SECRET_KEY=${SERVERA_SECRET_KEY}
      - ORIGIN_DOMAIN=${SERVERA_ENDPOINT}
      - AWS_REGION=us-east-1
      - PORT=8000
    restart: unless-stopped

  s3-proxy-serverB:
    image: s4l3h1/s3proxy:latest
    ports:
      - "8002:8000"
    environment:
      - CLIENT_ACCESS_KEY=${CLIENT_ACCESS_KEY}
      - CLIENT_SECRET_KEY=${CLIENT_SECRET_KEY}
      - ORIGIN_ACCESS_KEY=${SERVERB_ACCESS_KEY}
      - ORIGIN_SECRET_KEY=${SERVERB_SECRET_KEY}
      - ORIGIN_DOMAIN=${SERVERB_ENDPOINT}
      - AWS_REGION=us-east-1
      - PORT=8000
    restart: unless-stopped

  haproxy:
    image: haproxy:2.9-alpine
    ports:
      - "8000:8000"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on:
      - s3-proxy-serverA
      - s3-proxy-serverB
    restart: unless-stopped
```

#### 3. Create `haproxy.cfg`

```haproxy
global
    log stdout format raw local0
    maxconn 4096

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000ms
    timeout client  50000ms
    timeout server  50000ms

frontend s3_frontend
    bind *:8000
    default_backend s3_backends

backend s3_backends
    balance roundrobin
    option httpchk GET /healthz
    http-check expect status 200
    
    server serverA s3-proxy-serverA:8000 check inter 5000 rise 2 fall 3
    server serverB s3-proxy-serverB:8000 check inter 5000 rise 2 fall 3
```

#### 4. Deploy

```bash
docker-compose up -d
```

### Health Checks

The proxy provides a health check endpoint:

```bash
# Check backend health
curl http://localhost:8000/healthz

# Response: {"status": "ok"} with HTTP 200 if origin is healthy
# Response: {"status": "nok"} with HTTP 450 if origin is down
```

HAProxy automatically removes unhealthy backends from rotation based on health checks (every 5 seconds).


## How It Works

### Single Request Flow

1. **Request Interception**: Proxy receives requests signed with client credentials
2. **Client Authentication**: Validates `X-Amz-Credential` matches `CLIENT_ACCESS_KEY`
3. **Signature Validation**: Verifies AWS Signature V4 using `CLIENT_SECRET_KEY`
4. **URL Re-signing**: 
   - Extracts signature components from query parameters
   - Reconstructs canonical request with origin domain
   - Calculates new AWS Signature V4 with `ORIGIN_SECRET_KEY`
   - Replaces signature in query string
5. **Request Forwarding**: Forwards re-signed request to origin S3 service
6. **Response Streaming**: Streams response back to client

### Multi-Backend Flow (with HAProxy)

1. **HAProxy Health Checks**: Continuously polls `/healthz` on each backend (every 5 seconds)
2. **Backend Status**: Each proxy checks its origin S3 server health via HEAD request
3. **Load Distribution**: HAProxy round-robins requests across healthy backends only
4. **Automatic Failover**: Unhealthy backends removed after 3 failed checks, restored after 2 successful checks
5. **Transparent to Client**: Client uses same credentials regardless of which backend serves the request

## API Endpoints

### S3 Operations
The proxy handles all paths and HTTP methods:

- `GET /{path:path}` - Get objects, list buckets, etc.
- `POST /{path:path}` - Create multipart uploads, etc.
- `PUT /{path:path}` - Upload objects, create buckets, etc.
- `DELETE /{path:path}` - Delete objects, buckets, etc.
- `HEAD /{path:path}` - Get object metadata

### Health Check

- `GET /healthz` - Check origin server health
  - Returns `{"status": "ok"}` with HTTP 200 if origin returns 2xx
  - Returns `{"status": "nok"}` with HTTP 450 if origin is unreachable or returns non-2xx

## Example Request Flow

```
Client Request (signed with CLIENT credentials):
GET https://s3.mydomain.com/bucket/object.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=CLIENT_KEY.../20241201/us-east-1/s3/aws4_request&X-Amz-Date=20241201T120000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=client_signature

Proxy Processing:
1. Validates CLIENT_KEY matches CLIENT_ACCESS_KEY
2. Verifies client_signature using CLIENT_SECRET_KEY
3. Re-calculates signature for origin using ORIGIN_ACCESS_KEY/ORIGIN_SECRET_KEY
4. Replaces X-Amz-Signature and X-Amz-Credential

Forwarded Request (signed with ORIGIN credentials):
GET https://s3.backend.com/bucket/object.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ORIGIN_KEY.../20241201/us-east-1/s3/aws4_request&X-Amz-Date=20241201T120000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=origin_signature
```

## Error Handling

The proxy returns appropriate HTTP error responses for:

- **400 Bad Request**: Client access key mismatch, invalid signature format, invalid S3 path
- **403 Forbidden**: Invalid AWS signature (client signature verification failed)
- **450 Backend Unavailable**: Origin S3 server health check failed (health check endpoint only)
- **Upstream errors**: Forwards status codes from origin S3 service

## Security Considerations

- Store `CLIENT_SECRET_KEY` and `ORIGIN_SECRET_KEY` securely (use secrets management in production)
- Use `.env` files for local development, never commit to version control
- The dual-credential system prevents clients from directly accessing origin servers
- Client credentials can be rotated without changing origin credentials (or vice versa)
- The proxy validates client access keys to prevent unauthorized re-signing
- All original request headers and body are preserved
- HTTPS recommended for production deployment
- HAProxy health checks ensure only healthy backends receive traffic


## License

MIT License

## Contributing

1. Fork the repository: https://github.com/salehi/s3proxy
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Links

- **GitHub Repository**: https://github.com/salehi/s3proxy
- **Docker Hub**: https://hub.docker.com/r/s4l3h1/s3proxy
- **Issues**: https://github.com/salehi/s3proxy/issues