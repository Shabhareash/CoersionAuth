#!/bin/bash

echo "===================="
echo "1. RustLogger"
echo "2. Vector"
echo "===================="
read -p "Choice: " choice

echo
echo "===== System Before Run ====="
echo "CPU:"
lscpu | grep -E 'Model name|CPU MHz|CPU max MHz|CPU min MHz'
echo
echo "Memory:"
free -h
echo

case "$choice" in
    1)
        echo "===== Running RustLogger ====="
        /usr/bin/time -v \
        ./target/release/my_scanner auth_1m.log auth.yaml
        ;;
    2)
        echo "===== Running Vector ====="
        /usr/bin/time -v \
        /home/shabh/.vector/script.sh
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo
echo "===== System After Run ====="
echo "Current CPU MHz:"
grep "cpu MHz" /proc/cpuinfo | head -1

echo
echo "Memory:"
free -h