"""Interleave many targets' probe lists (pure Python, no scapy, unit-tested).

Each target's probes go out at least `gap` seconds apart, measured from when
the previous probe to that target actually left (design doc: probes ~150 ms
apart). A new target is started every `stagger` seconds, so with
stagger = probes_per_target / max_pps the overall send rate stays near the cap
while dozens of targets are in progress at once. The token bucket in the
prober still enforces the hard cap; this just keeps the queue fed.
"""
import heapq


class Interleaver:
    def __init__(self, plists, gap, stagger, t0):
        self._src = iter(plists)
        self._pending = next(self._src, None)
        self._next_start = t0
        self._heap = []
        self._seq = 0
        self.gap = gap
        self.stagger = stagger
        self.active = 0  # targets started but not finished

    def pop(self, now):
        """Next probe to send: (due_time, plist, index), or None when finished."""
        start_due = self._next_start if self._pending is not None else None
        if start_due is not None and (not self._heap or start_due <= self._heap[0][0]):
            plist = self._pending
            self._pending = next(self._src, None)
            # If the sender fell behind, don't let a backlog of starts pile up.
            self._next_start = max(start_due, now) + self.stagger
            self.active += 1
            return start_due, plist, 0
        if self._heap:
            due, _, plist, idx = heapq.heappop(self._heap)
            return due, plist, idx
        return None

    def done(self, plist, idx, sent_at):
        """Tell the scheduler probe idx of plist left at sent_at."""
        if idx + 1 < len(plist):
            self._seq += 1
            heapq.heappush(self._heap, (sent_at + self.gap, self._seq, plist, idx + 1))
        else:
            self.active -= 1


def stagger_for(n_probes, max_pps, headroom=1.1):
    """Seconds between target starts so the average rate stays under max_pps."""
    return n_probes / max_pps * headroom
