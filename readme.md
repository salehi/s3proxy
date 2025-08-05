# S3 URL Re-signing Proxy

[![Docker Hub](https://img.shields.io/docker/pulls/s4l3h1/s3proxy)](https://hub.docker.com/r/s4l3h1/s3proxy)
[![GitHub](https://img.shields.io/github/stars/salehi/s3proxy?style=social)](https://github.com/salehi/s3proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Starlette-based proxy service that enables you to serve your custom S3 service under a different domain while maintaining AWS Signature V4 compatibility.

## Problem

When you have a custom S3 service running on `s3.example.com` and want to serve it under `s3.mydomain.com`, AWS Signature V4 authentication breaks because the signature includes the host header in its calculation. Simply proxying requests fails because:

- DNS CNAME causes clients to sign URLs for `s3.mydomain.com` but the origin server expects `s3.example.com`
- Reverse proxy with host header rewriting still has signatures calculated for the wrong domain

## Solution

This proxy intercepts requests, validates the original signature, and re-signs the URL with the correct origin domain before forwarding the request.

## Features

- ✅ AWS Signature V4 re-signing on-the-fly
- ✅ Support for all HTTP methods (GET, POST, PUT, DELETE, HEAD)
- ✅ Streaming responses for efficient memory usage
- ✅ Environment variable configuration
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
poetry install
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ACCESS_KEY` | Your S3 access key | `your_access_key_here` |
| `AWS_SECRET_KEY` | Your S3 secret key | `your_secret_key_here` |
| `ORIGIN_DOMAIN` | Original S3 service domain | `s3.example.com` |
| `AWS_REGION` | AWS region | `us-east-1` |
| `PORT` | Server port | `8000` |

## Usage

### Set Environment Variables

```bash
export AWS_ACCESS_KEY="your_actual_access_key"
export AWS_SECRET_KEY="your_actual_secret_key"
export ORIGIN_DOMAIN="s3.example.com"
export AWS_REGION="us-east-1"
export PORT="8000"

python app.py
```


Then run:
```bash
python app.py
```

### Docker

#### Using Pre-built Image from Docker Hub

```bash
# Pull the latest image
docker pull s4l3h1/s3proxy:latest

# Run with environment variables
docker run -p 8000:8000 \
  -e AWS_ACCESS_KEY="your_key" \
  -e AWS_SECRET_KEY="your_secret" \
  -e ORIGIN_DOMAIN="s3.example.com" \
  -e AWS_REGION="us-east-1" \
  s4l3h1/s3proxy:latest
```


## How It Works

1. **Request Interception**: Proxy receives requests intended for `s3.mydomain.com`
2. **Signature Validation**: Validates that the `X-Amz-Credential` matches your configured access key
3. **URL Re-signing**: 
   - Extracts signature components from query parameters
   - Reconstructs canonical request with origin domain (`s3.example.com`)
   - Calculates new AWS Signature V4 with your secret key
   - Replaces signature in query string
4. **Request Forwarding**: Forwards re-signed request to origin S3 service
5. **Response Streaming**: Streams response back to client

## API Endpoints

The proxy handles all paths and HTTP methods:

- `GET /{path:path}` - Get objects, list buckets, etc.
- `POST /{path:path}` - Create multipart uploads, etc.
- `PUT /{path:path}` - Upload objects, create buckets, etc.
- `DELETE /{path:path}` - Delete objects, buckets, etc.
- `HEAD /{path:path}` - Get object metadata

## Example Request Flow

```
Client Request:
GET https://s3.mydomain.com/bucket/object.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA.../20241201/us-east-1/s3/aws4_request&X-Amz-Date=20241201T120000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=original_signature

Proxy Processing:
1. Validates AKIA... matches AWS_ACCESS_KEY
2. Re-calculates signature for s3.example.com
3. Replaces X-Amz-Signature with new_signature

Forwarded Request:
GET https://s3.example.com/bucket/object.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA.../20241201/us-east-1/s3/aws4_request&X-Amz-Date=20241201T120000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=new_signature
```

## Error Handling

The proxy returns appropriate HTTP error responses for:

- **400 Bad Request**: Access key mismatch, invalid signature format
- **Upstream errors**: Forwards status codes from origin S3 service

## Security Considerations

- Store `AWS_SECRET_KEY` securely (use secrets management in production)
- The proxy validates access keys to prevent unauthorized re-signing
- All original request headers and body are preserved
- HTTPS recommended for production deployment


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