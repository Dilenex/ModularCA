#!/bin/sh
# First start: no config.yaml yet, so run the headless bootstrap from the files the operator put in
# the config volume (bootstrap.yaml, setup-database.yaml, and the parts of config.yaml that name
# the node). The bootstrap prints the initial administrator password once; the pod's journal is
# where it lands, so read it there and change it at first sign-in. Every later start just runs.
set -e
cd /opt/modularca
if [ ! -f config/config.yaml ] || [ ! -f config/db.yaml ]; then
  echo "modularca-node: no config.yaml or db.yaml; running headless bootstrap"
  ./ModularCA.API --bootstrap
fi
exec ./ModularCA.API "$@"
