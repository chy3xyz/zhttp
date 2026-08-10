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
