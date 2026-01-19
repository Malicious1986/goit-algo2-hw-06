import json
import time
import math
import mmh3


class HyperLogLog:
    def __init__(self, p=14):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0**-r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def load_ip_addresses(filename):
    ip_addresses = []
    error_count = 0

    with open(filename, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            line = line.strip()
            if not line:
                continue
            try:
                log_entry = json.loads(line)
                if "remote_addr" in log_entry:
                    ip_address = log_entry["remote_addr"]
                    if ip_address:
                        ip_addresses.append(ip_address)
                else:
                    error_count += 1

            except json.JSONDecodeError:
                error_count += 1
            except Exception as e:
                error_count += 1

    return ip_addresses


def exact_count(ip_addresses):
    return len(set(ip_addresses))


def hyperloglog_count(ip_addresses, p=14):
    hll = HyperLogLog(p=p)
    for ip in ip_addresses:
        hll.add(ip)
    return hll.count()


def compare_methods(filename):
    ip_addresses = load_ip_addresses(filename)

    start_time = time.perf_counter()
    exact_unique = exact_count(ip_addresses)
    exact_time = time.perf_counter() - start_time

    start_time = time.perf_counter()
    hll_unique = hyperloglog_count(ip_addresses, p=14)
    hll_time = time.perf_counter() - start_time

    print("\nРезультати порівняння:")
    print(f"{'': <30} {'Точний підрахунок': >20} {'HyperLogLog': >20}")
    print(f"{'Унікальні елементи': <30} {exact_unique: >20.1f} {hll_unique: >20.1f}")
    print(f"{'Час виконання (сек.)': <30} {exact_time: >20.4f} {hll_time: >20.4f}")


if __name__ == "__main__":
    log_file = "lms-stage-access.log"
    compare_methods(log_file)
