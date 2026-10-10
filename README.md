# QKD-PQC prototype benchmarks (cloud run)

Run: Actions tab -> bench -> Run workflow. When it finishes, download the `filled-table` artifact (filled_table.md)
and the `results-*` artifacts.

Notes for the paper: three GitHub-hosted VMs (shared, virtualised). Each runs its own loopback mock key server,
so the Z-NOC-to-R-NOC round-trip time is not measured. Roles are labels on three different runner types.

## Round-trip-time sweep (second workflow)
Actions tab -> `rtt-sweep` -> Run workflow. It adds an emulated delay to the loopback interface (`tc netem`,
RTT = 2 x one-way delay; 0, 10, 50 and 100 ms) and measures the ETSI 014 key fetch (new connection and keep-alive)
and classical vs hybrid TLS handshakes at each RTT. Download the `rtt-sweep` artifact (`rtt_sweep.md`, `rtt_sweep.json`).
First run builds OpenSSL 3.5 (about 4 minutes); later runs use the cache.
State in the paper that the RTT is emulated, not measured on a real path, and that the mock fetch has no TLS.

## Emulated Z-NOC to R-NOC uplink with a real AES-256-GCM tunnel (third workflow)
Actions tab -> `topo-bench` -> Run workflow. Two network namespaces (Z-NOC, R-NOC) joined by a delayed link; the tunnel
key is HKDF(K_QKD || K_PQC || K_ECDHE) installed as a kernel ESP AES-256-GCM tunnel (`ip xfrm`). Reports uplink
throughput (plain vs ESP vs ESP with a key refresh every second), the cost of one refresh, and the cost and kernel memory
of refreshing 100 and 1000 tunnels at once. Download the `topo-results` artifact (`topo_results.md`, `topo_results.json`).
If the kernel lacks ESP/AES-GCM the run stops with a clear message in the log and `topo_results.md`.
