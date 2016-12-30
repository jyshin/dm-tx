#!/bin/bash

NAME="dm-tx"

#get the final stats
echo "Final stats:"
sudo dmsetup table "${NAME}" && sudo dmsetup status "${NAME}"
sudo dmsetup remove "${NAME}"
sudo rmmod "./${NAME}_mod.ko"
