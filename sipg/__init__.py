"""
SIPG - Shodan IP Grabber

A professional command-line tool for searching IP addresses using Shodan API.
"""

__version__ = "2.0.2"
__author__ = "Mahbob Alam"
__email__ = "emptymahbob@gmail.com"
__description__ = "A professional command-line tool for searching IP addresses using Shodan API"

from .core import ShodanIPGrabber
from .config import Config

__all__ = ["ShodanIPGrabber", "Config"] 