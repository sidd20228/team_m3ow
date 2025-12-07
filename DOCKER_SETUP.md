# Docker Setup Guide for WAF Application

This guide provides instructions for running the WAF application with Docker and Docker Compose.

## Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- Docker Compose (usually included with Docker Desktop)
- At least 4GB RAM allocated to Docker

## Quick Start

### 1. Build and Run with Docker Compose

```bash
# Navigate to the project directory
cd c:\Users\ARYAN\1.9\waf\WAF_SETUP

# Start all services
docker-compose -f docker-compose-new.yml up --build

# Run in background (detached mode)
docker-compose -f docker-compose-new.yml up -d --build
```

### 2. Access the Application

Once all services are running:

- **FastAPI Application**: http://localhost:8001
- **Health Check**: http://localhost:8001/health
- **OpenResty (Nginx)**: http://localhost/
- **Redis**: localhost:6379
- **MongoDB**: localhost:27017

### 3. View Logs

```bash
# All services
docker-compose -f docker-compose-new.yml logs -f

# Specific service
docker-compose -f docker-compose-new.yml logs -f waf_app
docker-compose -f docker-compose-new.yml logs -f openresty
docker-compose -f docker-compose-new.yml logs -f redis
```

### 4. Stop Services

```bash
# Stop and remove containers
docker-compose -f docker-compose-new.yml down

# Also remove volumes (data)
docker-compose -f docker-compose-new.yml down -v
```

## Container Details

### FastAPI WAF Application
- **Image**: Python 3.11-slim
- **Port**: 8001
- **Dependencies**: Redis, MongoDB
- **Features**: Anomaly detection, rule management, WebSocket logs

### OpenResty (Nginx + Lua)
- **Image**: openresty/openresty:centos
- **Port**: 80
- **Purpose**: Reverse proxy with Lua WAF chain

### Redis
- **Image**: redis:7-alpine
- **Port**: 6379
- **Storage**: Docker volume `redis_data`
- **Persistence**: AOF (Append Only File) enabled

### MongoDB
- **Image**: mongo:7
- **Port**: 27017
- **Storage**: Docker volume `mongodb_data`
- **Default Credentials**: admin/password123

## Environment Variables

Copy `.env.example` to `.env` and customize as needed:

```bash
cp .env.example .env
```

## Manual Docker Commands

If you prefer not to use Docker Compose:

### Build FastAPI Image
```bash
docker build -t waf-fastapi -f Dockerfile .
```

### Build OpenResty Image
```bash
docker build -t waf-openresty -f Dockerfile.openresty .
```

### Run Redis
```bash
docker run -d --name waf_redis -p 6379:6379 redis:7-alpine
```

### Run MongoDB
```bash
docker run -d --name waf_mongodb -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin \
  -e MONGO_INITDB_ROOT_PASSWORD=password123 \
  mongo:7
```

### Run FastAPI
```bash
docker run -d --name waf_fastapi -p 8001:8001 \
  -e REDIS_URL=redis://host.docker.internal:6379 \
  -e MONGO_URI=mongodb://admin:password123@host.docker.internal:27017/waf_db \
  waf-fastapi
```

### Run OpenResty
```bash
docker run -d --name waf_openresty -p 80:80 \
  -v $(pwd)/nginx-docker.conf:/usr/local/openresty/nginx/conf/nginx.conf \
  -v $(pwd)/lua:/usr/local/openresty/nginx/lua \
  waf-openresty
```

## Networking

By default, Docker Compose creates a `waf_network` bridge network. All containers communicate using service names:

- `redis` (port 6379)
- `mongodb` (port 27017)
- `waf_app` (port 8001)
- `openresty` (port 80)

## Volumes

- `redis_data`: Persistent Redis data
- `mongodb_data`: Persistent MongoDB data
- Model files are mounted from host for quick updates

## Health Checks

All services include health checks:

```bash
# Check service health
docker-compose -f docker-compose-new.yml ps

# Manual health check
curl http://localhost:8001/health
```

## Troubleshooting

### Port Already in Use
```bash
# Find and stop conflicting container
docker ps
docker stop <container_id>
```

### Redis Connection Error
```bash
# Test Redis connection
docker exec waf_redis redis-cli ping
```

### MongoDB Connection Error
```bash
# Test MongoDB connection
docker exec waf_mongodb mongosh --eval "db.adminCommand('ping')"
```

### Out of Memory
Increase Docker's memory allocation in Docker Desktop settings.

### Rebuild Without Cache
```bash
docker-compose -f docker-compose-new.yml build --no-cache
```

## Performance Tuning

For production deployments:

1. **Increase worker processes** in nginx.conf: `worker_processes auto;`
2. **Adjust Redis memory**: Add `maxmemory` policy
3. **Enable MongoDB compression**: Add compression codec in connection string
4. **Use volume mounts** for logs persistence
5. **Set resource limits** in docker-compose.yml

## Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [OpenResty Documentation](https://openresty.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
