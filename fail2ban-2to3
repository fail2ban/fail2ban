#!/bin/bash
# This script carries out conversion of fail2ban to python3
# A backup of any converted files are created with ".bak"
# extension

set -eu

if 2to3 -w --no-diffs bin/* fail2ban;then
  echo "Success!" >&2
  exit 0
else
  echo "Fail!" >&2
  exit 1
fi
