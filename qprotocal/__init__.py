#!/usr/bin/env python
"""A library that provides a Python interface to the Android QQ Protocal"""
from sys import version_info
from .base import QQObject
from .qq import QQ
from .version import __version__

__author__ = 'gorgiaxx@gmail.com'

__all__ = [
    'QQ'
]

# QQ Number
qq_number = '2537568158'
# QQ Password
qq_password = '123456789'