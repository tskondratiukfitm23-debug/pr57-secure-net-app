"""Захист від brute force і DoS.

1. TokenBucket на IP — загальний ліміт запитів (захист від флуду/DoS): місткість RATE_CAPACITY,
   поповнення RATE_REFILL токенів/с. Перевищення -> 429 + Retry-After.
2. LoginGuard:
   * ліміт спроб логіну з одного IP (LOGIN_IP_RPM за 60 с, фіксоване вікно) — захист від
     перебору багатьох логінів з однієї адреси (password spraying);
   * лічильник НЕВДАЛИХ спроб на обліковий запис (LOGIN_MAX_FAILS за LOGIN_WINDOW) ->
     тимчасове блокування LOCKOUT_BASE с, кожне наступне вдвічі довше (макс. 1 год);
   * успішний вхід скидає лічильник.
"""
import threading
import time
from typing import Dict, Tuple

from server import config


class TokenBucket:
    def __init__(self, capacity: int = None, refill: float = None):
        self.capacity = capacity or config.RATE_CAPACITY
        self.refill = refill or config.RATE_REFILL
        self._b: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> Tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._b.get(key, (float(self.capacity), now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill)
            if tokens >= 1:
                self._b[key] = (tokens - 1, now)
                return True, 0.0
            self._b[key] = (tokens, now)
            return False, (1 - tokens) / self.refill


class LoginGuard:
    def __init__(self, max_fails=None, window=None, lockout_base=None, ip_rpm=None):
        self.max_fails = max_fails or config.LOGIN_MAX_FAILS
        self.window = window or config.LOGIN_WINDOW
        self.lockout_base = lockout_base or config.LOCKOUT_BASE
        self.ip_rpm = ip_rpm or config.LOGIN_IP_RPM
        self._fails: Dict[str, list] = {}        # user -> [timestamps]
        self._locks: Dict[str, Tuple[float, int]] = {}  # user -> (until, level)
        self._ip: Dict[str, Tuple[int, float]] = {}     # ip -> (count, window_start)
        self._lock = threading.Lock()

    def check(self, ip: str, user: str) -> Tuple[bool, str, int]:
        """(allowed, reason, retry_after)."""
        now = time.time()
        with self._lock:
            cnt, start = self._ip.get(ip, (0, now))
            if now - start >= 60:
                cnt, start = 0, now
            cnt += 1
            self._ip[ip] = (cnt, start)
            if cnt > self.ip_rpm:
                return False, "ip_rate", int(60 - (now - start)) + 1
            until, _ = self._locks.get(user, (0, 0))
            if until > now:
                return False, "locked", int(until - now) + 1
        return True, "", 0

    def fail(self, user: str) -> Tuple[int, int]:
        """Реєструє невдалу спробу. Повертає (кількість у вікні, тривалість блокування або 0)."""
        now = time.time()
        with self._lock:
            arr = [t for t in self._fails.get(user, []) if now - t < self.window] + [now]
            self._fails[user] = arr
            if len(arr) >= self.max_fails:
                _, level = self._locks.get(user, (0, 0))
                dur = min(self.lockout_base * (2 ** level), 3600)
                self._locks[user] = (now + dur, level + 1)
                self._fails[user] = []
                return len(arr), dur
            return len(arr), 0

    def success(self, user: str):
        with self._lock:
            self._fails.pop(user, None)
            until, level = self._locks.get(user, (0, 0))
            self._locks[user] = (0, max(0, level - 1)) if until else (0, 0)

    def status(self):
        now = time.time()
        with self._lock:
            return {u: int(t - now) for u, (t, _) in self._locks.items() if t > now}
