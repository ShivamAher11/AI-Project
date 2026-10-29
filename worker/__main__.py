"""Healthy placeholder process; analysis task execution is a later slice."""

import signal
import time

stopping = False


def stop(_signum, _frame):
    global stopping
    stopping = True


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
while not stopping:
    time.sleep(1)
