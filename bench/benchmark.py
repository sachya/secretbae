#!/usr/bin/env python3
"""Measures real latency for the operations README.md cites numbers for.

Run via bench/run.sh, which sets up an isolated daemon first -- this script assumes one is
already running and reachable. Every number this produces is a real measurement against a real
daemon over a real socket; nothing here is a stand-in or an estimate.
"""

import argparse
import json
import socket
import statistics
import subprocess
import time


def percentile(samples_ms, p):
    ordered = sorted(samples_ms)
    index = min(len(ordered) - 1, int(len(ordered) * p / 100))
    return ordered[index]


def summarize(samples_ms):
    return {
        "count": len(samples_ms),
        "min_ms": round(min(samples_ms), 3),
        "mean_ms": round(statistics.mean(samples_ms), 3),
        "p50_ms": round(percentile(samples_ms, 50), 3),
        "p90_ms": round(percentile(samples_ms, 90), 3),
        "p99_ms": round(percentile(samples_ms, 99), 3),
        "max_ms": round(max(samples_ms), 3),
    }


def bench_cli(argv, iterations, warmup):
    for _ in range(warmup):
        subprocess.run(argv, capture_output=True, check=True)
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        subprocess.run(argv, capture_output=True, check=True)
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def bench_resolve_socket(sock_path, token, path, iterations, warmup):
    def one_call():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        s.sendall(f"RESOLVE 1 {token} 1\n{path}\n".encode())
        f = s.makefile("rb")
        line = f.readline().decode().strip()
        if not line.startswith("VALUE"):
            raise RuntimeError(f"unexpected response: {line}")
        _, _, length = line.split(" ")
        f.read(int(length))
        s.close()

    for _ in range(warmup):
        one_call()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        one_call()
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, help="path to the secretbae binary")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--resolve-socket", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--path", default="bench/warm_secret")
    parser.add_argument("--profile", required=True, help="path to an exec profile TOML")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--out-json", required=True)
    args = parser.parse_args()

    results = {}

    results["secretbae get (CLI, warm)"] = summarize(
        bench_cli(
            [args.cli, "--socket", args.socket, "get", args.path, "--raw"],
            args.iterations,
            args.warmup,
        )
    )

    results["resolve socket round trip"] = summarize(
        bench_resolve_socket(
            args.resolve_socket, args.token, args.path, args.iterations, args.warmup
        )
    )

    results["secretbae exec (cold start)"] = summarize(
        bench_cli(
            [args.cli, "--socket", args.socket, "exec", "--profile", args.profile, "--", "/bin/true"],
            args.iterations,
            args.warmup,
        )
    )

    results["secretbae put (CLI)"] = summarize(
        bench_cli(
            [args.cli, "--socket", args.socket, "put", args.path, "--value", "bench-value"],
            args.iterations,
            args.warmup,
        )
    )

    print(json.dumps(results, indent=2))
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
