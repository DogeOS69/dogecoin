# Dogecoin Testnet Node (Docker)

Containerized Dogecoin testnet node for shadow fork development and testing.

## Quick Start

```bash
# From repo root
docker build -f contrib/docker/testnet-node/Dockerfile -t dogecoin-testnet:local .

# Run with default settings
docker run -d --name dogecoin-testnet \
  -p 44555:44555 -p 44556:44556 \
  -v testnet-data:/data \
  dogecoin-testnet:local

# Check sync progress
docker exec dogecoin-testnet dogecoin-cli -testnet getblockchaininfo
```

## Using Docker Compose

```bash
cd contrib/docker/testnet-node
docker-compose up -d

# View logs
docker-compose logs -f

# Check sync
docker-compose exec testnet-node dogecoin-cli getblockchaininfo

# Stop
docker-compose down
```

## Image Details

| Property | Value |
|----------|-------|
| Base | debian:bookworm-slim |
| Size | ~113MB |
| Build time | 5-10 minutes (compiles from source) |
| Binaries | dogecoind, dogecoin-cli (stripped) |

### Build Optimizations

- Multi-stage build (builder → runtime)
- Stripped binaries (dogecoind: 103MB → 5.2MB)
- Minimal runtime dependencies
- No wallet support (reduces attack surface)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOGECOIN_DATA` | `/data` | Blockchain data directory |
| `DOGECOIN_CONF` | `/config/dogecoin.conf` | Config file path |
| `RPC_USER` | - | RPC username (for healthcheck) |
| `RPC_PASS` | - | RPC password (for healthcheck) |

### Ports

| Port | Purpose |
|------|---------|
| 44555 | RPC (testnet) |
| 44556 | P2P (testnet) |

### Volumes

| Path | Purpose |
|------|---------|
| `/data` | Blockchain data (blocks, chainstate) |
| `/config` | Configuration files (mount read-only) |

## Configuration File

Create `config/dogecoin.conf`:

```ini
# Network
testnet=1
txindex=1

# RPC
server=1
rpcuser=myuser
rpcpassword=mypassword
rpcallowip=0.0.0.0/0
rpcbind=0.0.0.0

# Performance
dbcache=512
maxconnections=32
```

## Syncing from Scratch

Full testnet sync takes several hours. To speed up:

### Option 1: Let it sync
```bash
docker-compose up -d
# Wait... check progress with:
docker-compose exec testnet-node dogecoin-cli getblockchaininfo
```

### Option 2: Bootstrap from snapshot
```bash
# Stop the node
docker-compose down

# Extract snapshot into volume
docker run --rm -v testnet-data:/data -v ~/snapshots:/snapshots alpine \
  tar -xzf /snapshots/testnet-snapshot.tar.gz -C /data/testnet3/

# Start node
docker-compose up -d
```

## Creating Snapshots

Once synced, create a snapshot for faster bootstrapping:

```bash
# Stop node to ensure consistency
docker-compose stop

# Create tarball from volume
docker run --rm -v testnet-data:/data -v ~/snapshots:/snapshots alpine \
  tar -czf /snapshots/testnet-snapshot-$(date +%Y%m%d).tar.gz \
  -C /data/testnet3 blocks chainstate

# Restart
docker-compose start
```

## RPC Access

```bash
# From host (with port mapping)
curl -u myuser:mypassword \
  --data-binary '{"jsonrpc":"1.0","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:44555/

# Using dogecoin-cli inside container
docker exec dogecoin-testnet dogecoin-cli -testnet getblockchaininfo
```

## Healthcheck

The container includes a healthcheck that queries `getblockchaininfo` every 30s.
Check health status:

```bash
docker inspect --format='{{.State.Health.Status}}' dogecoin-testnet
```

## Troubleshooting

### Container exits immediately
Check logs: `docker logs dogecoin-testnet`

Common causes:
- Config file syntax error
- Data directory permissions
- Port already in use

### Sync stuck or slow
- Increase `dbcache` in config (requires more RAM)
- Check disk I/O: `docker stats dogecoin-testnet`
- Verify network connectivity

### RPC connection refused
- Ensure `rpcallowip` includes your client IP
- Check `rpcbind=0.0.0.0` is set
- Verify port mapping: `docker port dogecoin-testnet`

## Integration with Shadow Fork

This testnet node serves as the "canonical chain" source for shadow fork testing:

```bash
# Run shadow fork integration tests against this node
TESTNET_RPC_URL=127.0.0.1:44555 \
TESTNET_RPC_USER=myuser \
TESTNET_RPC_PASS=mypassword \
qa/rpc-tests/shadowfork_integration.py --srcdir=src
```

## Files

```
contrib/docker/testnet-node/
├── Dockerfile           # Multi-stage build
├── docker-compose.yml   # Orchestration
├── README.md            # This file
├── config/
│   └── dogecoin.conf    # Default config
└── scripts/
    ├── entrypoint.sh    # Container entrypoint
    └── create-snapshot.sh  # Snapshot helper
```
