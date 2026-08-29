import time
from collections import defaultdict

_counters = defaultdict(int)
_hist_sum = defaultdict(float)
_hist_count = defaultdict(int)
_started = time.time()

def inc(name: str, value: int = 1):
    _counters[name] += value

def observe(name: str, seconds: float):
    _hist_sum[name] += seconds
    _hist_count[name] += 1

def prometheus_text() -> str:
    lines = [
        "# HELP ruach_process_uptime_seconds Process uptime in seconds",
        "# TYPE ruach_process_uptime_seconds gauge",
        f"ruach_process_uptime_seconds {time.time()-_started:.3f}",
    ]
    for name, value in sorted(_counters.items()):
        safe = name.replace("-", "_").replace(".", "_")
        lines += [f"# TYPE ruach_{safe} counter", f"ruach_{safe} {value}"]
    for name, value in sorted(_hist_sum.items()):
        safe = name.replace("-", "_").replace(".", "_")
        lines += [f"# TYPE ruach_{safe}_seconds_sum counter", f"ruach_{safe}_seconds_sum {value:.6f}",
                  f"# TYPE ruach_{safe}_count counter", f"ruach_{safe}_count {_hist_count[name]}"]
    return "\n".join(lines) + "\n"
