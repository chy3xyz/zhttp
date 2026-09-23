# httpz.zig Benchmarks & Performance Guide

This directory contains micro-benchmarks and load testing guides for `httpz.zig`.

## Running In-Tree Micro-benchmarks

To run the built-in Zig micro-benchmarks:

```bash
zig build bench
```

### Sample Micro-benchmark Output

```text
=== httpz.zig Micro-benchmarks ===

1. HTTP Request Parser:
   Iterations: 1,000,000
   Total Time: 526.42 ms
   Latency:    526.42 ns/op
   Throughput: 1,899,635 ops/sec

2. Router Match & Dispatch:
   Iterations: 1,000,000
   Total Time: 210.00 ms
   Latency:    210.00 ns/op
   Throughput: 4,761,905 ops/sec
```

---

## HTTP/3 Micro-benchmarks

The HTTP/3 benchmark stands up a real `httpz.h3.Server` and `httpz.h3.Client`
over loopback and measures a single connection: 500 requests for a 1 KiB
response, then 3 requests for a 2 MiB response. It is opt-in because the HTTP/3
layer is:

```bash
zig build bench-h3 -Dh3=true
```

### Sample Output

```text
=== httpz.zig HTTP/3 Micro-benchmarks ===

TLS certificate: src/h3/test_cert.pem

H3 server listening on UDP
1. Small responses (1 KiB):
   Requested:   500
   Completed:   500
   Connections: 1
   Total Time:  1850.20 ms
   Latency:     3.70 ms/req (min 2.68 ms, max 7.53 ms)
   Throughput:  270 req/sec

2. Large response body (2 MiB):
   Requested:   3
   Completed:   3
   Connections: 1
   Total Time:  2410.00 ms
   Latency:     803.33 ms/req (min 780.10 ms, max 840.00 ms)
   Throughput:  2.61 MB/s
```

The benchmark exits non-zero when a request does not come back, so it can be
used as a regression check. It reads its TLS certificate at run time:
`src/h3/test_cert.pem` when it is there, otherwise `examples/cert/cert.pem`
(generate that one with `bash examples/gen_cert.sh`).

---

## Load Testing HTTP Server with `wrk`

To benchmark the HTTP/1.1 server throughput under real network loads:

1. Build and start the example HTTP server in ReleaseFast mode:
   ```bash
   zig build example_server_router -O ReleaseFast
   ./zig-out/bin/server_router
   ```

2. Run `wrk` with 12 threads and 400 connections:
   ```bash
   wrk -t12 -c400 -d30s http://127.0.0.1:8080/
   ```

---

## Load Testing HTTP/2 Server with `h2load`

To benchmark HTTP/2 multi-stream multiplexing performance:

```bash
h2load -n 100000 -c 100 -m 10 https://127.0.0.1:8443/
```
