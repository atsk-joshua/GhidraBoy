#!/usr/bin/env python3
"""Compatibility command: build the current Linux runtime through the single packager."""
from package_candidate import main

if __name__ == '__main__':
    main(default_platform='linux-x86_64')
