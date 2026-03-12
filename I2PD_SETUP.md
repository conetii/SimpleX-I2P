# I2PD Setup for SimpleX-I2P

This document explains the i2pd configuration required for successful LeaseSet publication and SimpleX-I2P server operation.

## Problem: LeaseSet Publication Failures

During initial testing (March 2026), we encountered persistent LeaseSet publication failures across multiple servers. The I2P network was recovering from DDoS attacks in February 2026, causing:

- Low tunnel creation success rates (40-60%)
- Floodfill router unresponsiveness
- "Publish confirmation was not received in 1800 milliseconds" errors

## Solution: Floodfill Mode

Enabling **floodfill mode** resolved the LeaseSet publication issue by:

1. Making the router part of the I2P network database infrastructure
2. Providing direct access to netDb operations
3. Improving tunnel creation success rate (82%+)
4. Ensuring reliable LeaseSet publication

## Configuration

### i2pd.conf Location

i2pd reads configuration from `/etc/i2pd/i2pd.conf` (not `/root/.i2pd/`).

### Required Settings

```ini
# Enable floodfill mode (critical for LeaseSet publication)
floodfill = true

# High bandwidth allocation
bandwidth = L

# I2P router port (must be open in firewall)
port = 4568
ipv4 = true
ipv6 = false

[limits]
# High transit tunnel count for network participation
transittunnels = 100
openfiles = 0
coresize = 0
ntcpsoft = 250
ntcphard = 500

[ntcp2]
enabled = true

[ssu2]
enabled = true
port = 4568

[sam]
# SAM API for SimpleX integration
enabled = true
address = 127.0.0.1
port = 7656
```

### tunnels.conf Settings

```ini
[simplex-smp]
type = server
host = 127.0.0.1
port = 5223
keys = simplex-smp.dat

# Reduced hop count for better reliability during network stress
inbound.length = 2
outbound.length = 2
inbound.quantity = 2
outbound.quantity = 2
```

## Installation Steps

1. **Install i2pd on host** (not in Docker):
```bash
sudo apt-get install i2pd
```

2. **Copy configuration files**:
```bash
sudo cp i2pd/i2pd.conf /etc/i2pd/i2pd.conf
sudo cp i2pd/tunnels.conf /etc/i2pd/tunnels.conf
```

3. **Open firewall port**:
```bash
sudo ufw allow 4568/tcp
sudo ufw allow 4568/udp
```

4. **Start i2pd**:
```bash
sudo systemctl enable i2pd
sudo systemctl start i2pd
```

5. **Wait for integration** (30-60 minutes):
   - Do NOT restart i2pd during this period
   - Monitor tunnel creation rate: `curl -s http://localhost:7070/ | grep "success rate"`
   - Target: 80%+ success rate

6. **Start SimpleX SMP server**:
```bash
docker-compose up -d smp-server
```

7. **Verify LeaseSet publication**:
```bash
./scripts/show-address.sh
```

## Why Floodfill Mode?

**Floodfill routers** are part of I2P's distributed network database (netDb). They:
- Store and distribute RouterInfo and LeaseSet records
- Respond to netDb lookup requests
- Provide redundancy for the network database

**Benefits for SimpleX-I2P:**
- Direct participation in netDb operations
- Higher priority for tunnel building
- Better connectivity to other floodfill routers
- More reliable LeaseSet publication

**Requirements:**
- Stable uptime (router should run continuously)
- Good network connection
- Sufficient resources (CPU/RAM/bandwidth)
- Open port 4568 (TCP/UDP)

## Troubleshooting

### LeaseSet not publishing

Check i2pd logs:
```bash
sudo tail -100 /var/log/i2pd/i2pd.log | grep -E "Destination|Publish|LeaseSet"
```

If you see "Publish confirmation was not received in 1800 milliseconds":
- Wait longer (30-60 minutes after restart)
- Check tunnel creation success rate (should be 80%+)
- Verify floodfill mode is enabled
- Ensure port 4568 is open

### Low tunnel creation rate

- Wait for router integration (10-15 minutes minimum)
- Check network connectivity
- Verify system time is synchronized (NTP)
- Increase uptime (avoid restarts)

### Docker i2pd conflicts

If you have both Docker i2pd and system i2pd running:
```bash
docker-compose stop i2pd
```

Only use system i2pd for production.

## Network Status During Testing

During March 2026 testing, the I2P network was experiencing:
- Tunnel creation rates of 40-60% (normal is 80%+)
- Floodfill router overload from February 2026 DDoS attacks
- Increased LeaseSet publication timeouts

Enabling floodfill mode improved our tunnel creation rate to 82% and enabled successful LeaseSet publication.

## References

- [I2P Network Database](https://geti2p.net/en/docs/how/network-database)
- [i2pd Documentation](https://i2pd.readthedocs.io/)
- [I2P Troubleshooting Guide](https://geti2p.net/en/faq#trouble)
- research.md - Detailed analysis of LeaseSet publication failures
