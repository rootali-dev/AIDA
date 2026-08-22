# Module MOD-06: Command-Line Interface Client (`ai-idactl`)

- **Subsystem:** User Interface / Administration
- **Language:** Go (Cobra CLI framework)
- **Priority:** `#p1`

---

## 1. Key Commands & Syntax

```bash
# Add or update port-based static firewall rules
ai-idactl rule add port <port_num> --action ALLOW

# Block an IP address or CIDR subnet
ai-idactl rule block ip <cidr_block>

# Inspect real-time traffic throughput and drop/pass counters
ai-idactl stats --realtime

# Check system health, daemon status, and loaded eBPF programs
ai-idactl status
```
