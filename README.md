# TLSHunter
Generic TCP + TLS/SNI Scanner

A high-performance asynchronous TCP and TLS/SNI scanner for probing large IP ranges, CIDRs, and custom target lists.

The scanner supports concurrent TCP connectivity checks, TLS handshakes with configurable SNI values, certificate name extraction, keyword matching, retry logic for transient failures, and a real-time terminal interface powered by Rich.

Designed for large-scale scanning workloads while minimizing false negatives caused by transient network conditions, packet loss, or upstream rate limiting.

## Features

- High-performance asynchronous scanning using `asyncio`
- TCP port probing with configurable concurrency
- TLS handshake support with custom SNI values
- Multiple SNI support per target
- Certificate SAN/Common Name extraction
- Keyword matching against certificate names
- CIDR, IP range, and file-based target loading
- Optional ICMP ping filtering before scanning
- Concurrent TCP → TLS pipeline mode for improved throughput
- Automatic retry logic for transient failures
- Rich live terminal interface with:
  - Progress tracking
  - Live event feed
  - Success monitoring
  - Throughput metrics
  - ETA estimation
- Graceful shutdown with partial result saving
- Atomic output file writing
- IPv4 and IPv6 support
- Logging support for debugging and troubleshooting

---

## Installation

### Requirements

- Python 3.10+
- Linux/macOS recommended
- `ping` binary (optional, for `--ping` mode)

Install dependencies:

```bash
pip install rich cryptography
````

Clone the repository:

```bash
git clone <your-repository-url>
cd <repository-name>
```

---

## Usage

### Basic Scan

Scan a single IP:

```bash
python scanner.py 1.2.3.4
```

Scan a CIDR range:

```bash
python scanner.py 142.250.0.0/16
```

Scan targets from file:

```bash
python scanner.py -f targets.txt
```

---

## TLS/SNI Scanning

Probe TLS using a custom SNI:

```bash
python scanner.py 1.2.3.4 --sni example.com
```

Try multiple SNI values:

```bash
python scanner.py \
  -f ips.txt \
  --sni example.com \
  --sni api.example.com
```

Perform a no-SNI TLS probe:

```bash
python scanner.py 1.2.3.4 --sni ""
```

---

## Keyword Matching

Match certificate names against keywords:

```bash
python scanner.py \
  -f cidrs.txt \
  --sni vercel.com \
  --match vercel,now.sh
```

Matched results are highlighted in the interface and can optionally be saved exclusively:

```bash
python scanner.py \
  -f cidrs.txt \
  --sni vercel.com \
  --match vercel \
  --matched-only
```

---

## Ping Filtering

Ping targets before scanning to reduce unnecessary connection attempts:

```bash
python scanner.py \
  -f targets.txt \
  --ping
```

Only ping-responsive hosts continue to TCP/TLS scanning.

---

## TCP-Only Scanning

Run a TCP connectivity scan without TLS:

```bash
python scanner.py \
  -f ips.txt \
  --no-tls
```

Custom port example:

```bash
python scanner.py \
  142.250.0.0/16 \
  --port 443
```

---

## TLS-Only Scanning

Skip standalone TCP probing and attempt TLS directly:

```bash
python scanner.py \
  -f targets.txt \
  --no-tcp \
  --sni example.com
```

---

## High-Concurrency Scanning

Increase worker count for larger scans:

```bash
python scanner.py \
  142.250.0.0/16 \
  --workers 800 \
  --tls-workers 400
```

Example with retries disabled for maximum speed:

```bash
python scanner.py \
  -f targets.txt \
  --retries 0
```

---

## Examples

Scan IPs from file with TLS SNI:

```bash
python scanner.py \
  -f hosts.txt \
  --sni example.com \
  -o results.txt
```

Scan CIDRs and match certificate names:

```bash
python scanner.py \
  -f cidrs.txt \
  --ping \
  --sni vercel.com \
  --match vercel,now.sh
```

Large TCP scan:

```bash
python scanner.py \
  142.250.0.0/16 \
  --port 443 \
  --workers 800
```

Disable TCP→TLS pipeline mode:

```bash
python scanner.py \
  -f ips.txt \
  --sni example.com \
  --no-pipeline
```

---

## Target Formats

The scanner supports multiple input formats.

### Single IP

```text
1.2.3.4
```

### CIDR

```text
10.0.0.0/24
```

### IP Range

```text
1.1.1.1-1.1.1.50
```

### File Input

Target files support:

* One entry per line
* CIDRs
* IP ranges
* Comments using `#`

Example:

```text
# Production ranges
1.2.3.4
10.0.0.0/24
192.168.1.1-192.168.1.50
```

---

## Output Format

Results are written atomically to the output file.

Example:

```text
# Generated 2026-05-28T00:00:00+00:00
# matched_keywords=vercel,now.sh
# rows=2
# columns: ip<TAB>sni<TAB>matched<TAB>cipher<TAB>cert_names

1.2.3.4    vercel.com    1    TLS_AES_256_GCM_SHA384    vercel.com
5.6.7.8    vercel.com    0    TLS_CHACHA20_POLY1305_SHA256    edge.example.net
```

Fields:

| Field        | Description                       |
| ------------ | --------------------------------- |
| `ip`         | Target IP address                 |
| `sni`        | TLS Server Name Indication used   |
| `matched`    | Keyword match result (`0` or `1`) |
| `cipher`     | Negotiated TLS cipher             |
| `cert_names` | Certificate SAN/CN names          |

---

## Command Line Options

| Option           | Description                         |
| ---------------- | ----------------------------------- |
| `-f, --file`     | File containing targets             |
| `-o, --output`   | Output file                         |
| `--sni`          | SNI hostname (repeatable)           |
| `--match`        | Comma-separated keyword matching    |
| `--matched-only` | Save only matched results           |
| `--port`         | TCP/TLS port                        |
| `--ping`         | Enable ICMP ping filtering          |
| `--no-tcp`       | Skip TCP probe                      |
| `--no-tls`       | Skip TLS probe                      |
| `--no-pipeline`  | Disable concurrent TCP→TLS pipeline |
| `--tcp-timeout`  | TCP timeout                         |
| `--tls-timeout`  | TLS timeout                         |
| `--ping-timeout` | Ping timeout                        |
| `--retries`      | Retry transient failures            |
| `--retry-delay`  | Base retry delay                    |
| `--workers`      | TCP/Ping concurrency                |
| `--tls-workers`  | TLS concurrency                     |
| `--log-file`     | Log file path                       |
| `-v`             | Verbose logging                     |

---

## Retry Behavior

The scanner distinguishes between deterministic and transient failures.

### Deterministic Failures

These fail immediately without retry:

* `ECONNREFUSED`
* `EHOSTUNREACH`
* `ENETUNREACH`
* `ConnectionRefusedError`

### Transient Failures

These are retried using exponential backoff with jitter:

* Timeouts
* Temporary socket failures
* Resource exhaustion (`EMFILE`, `ENOBUFS`)
* Temporary network instability

This significantly reduces false negatives during high-throughput scans.

---

## Live Interface

The terminal interface provides real-time visibility into scan progress.

Displayed metrics include:

* Total targets
* Tested targets
* Successful probes
* Failed probes
* Errors
* Throughput (IPs/sec)
* Elapsed time
* Estimated completion time
* Pipeline statistics
* Success feed
* Live event stream

---

## Logging

Logs are written to:

```text
scanner.log
```

Enable verbose output:

```bash
python scanner.py -v
```

Debug logging:

```bash
python scanner.py -vv
```

---

## Performance Notes

For large scans:

* Increase `--workers` for TCP-heavy workloads
* Increase `--tls-workers` when TLS handshakes are the bottleneck
* Raise file descriptor limits if needed:

```bash
ulimit -n 100000
```

Recommended settings for large CIDR scans:

```bash
python scanner.py \
  -f large.txt \
  --workers 1000 \
  --tls-workers 500
```

Actual performance depends on:

* Network quality
* OS socket limits
* Upstream rate limiting
* Target responsiveness
* TLS handshake latency

---

## Disclaimer

This tool is intended for authorized network testing, infrastructure validation, and research purposes only.

Ensure you have permission before scanning networks you do not own or manage.

```
