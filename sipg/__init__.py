"""
SIPG — Shodan IP Grabber

A professional command-line tool for searching IP addresses using Shodan API.
"""

__version__ = "2.1.5"
__author__ = "Mahbob Alam"
__email__ = "emptymahbob@gmail.com"
__long_name__ = "Shodan IP Grabber"
__description__ = (
    "SIPG (Shodan IP Grabber) — search and collect assets via Shodan API and free modes."
)

from .core import ShodanIPGrabber
from .config import Config

__all__ = ["ShodanIPGrabber", "Config"]
