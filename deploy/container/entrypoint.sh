#!/bin/sh
# The image's entrypoint, for every container the pod runs from it.
#
# First start: no config.yaml yet, so run the headless bootstrap from the files the operator put in
# the config volume (bootstrap.yaml, setup-database.yaml, and the parts of config.yaml that name
# the node). The bootstrap prints the initial administrator password once; the pod's journal is
# where it lands, so read it there and change it at first sign-in. Every later start just runs.
#
# Only a process that will hold the control role may bootstrap. In the pod the signer starts
# from the same image with the same volume, and two processes racing to create the keystore in
# one directory is the thing this check exists to prevent: the signer waits for the node's
# bootstrap to have happened instead. The identity init containers pass their own role.
set -e
cd /opt/modularca

# --bootstrap-only: do the first-start bootstrap if it is needed and stop, serving nothing. This
# is what the pod's first init container runs, so that "is this install configured yet" is
# decided once, by one process, before anything else from the image starts.
bootstrap_only=no
if [ "${1:-}" = "--bootstrap-only" ]; then
  bootstrap_only=yes
  shift
fi

wants_bootstrap=yes
for arg in "$@"; do
  case "$arg" in
    --role)      expect_role=yes ;;
    --role=*)    case "${arg#--role=}" in *signer*|*ingress*) wants_bootstrap=no ;; esac ;;
    *)           if [ "${expect_role:-}" = yes ]; then
                   case "$arg" in *signer*|*ingress*) wants_bootstrap=no ;; esac
                   expect_role=
                 fi ;;
  esac
done

if [ ! -f config/config.yaml ] || [ ! -f config/db.yaml ]; then
  if [ "$wants_bootstrap" = yes ]; then
    echo "modularca: no config.yaml or db.yaml; running headless bootstrap"
    ./ModularCA.API --bootstrap
  else
    echo "modularca: waiting for the node to bootstrap (no config.yaml or db.yaml yet)"
    until [ -f config/config.yaml ] && [ -f config/db.yaml ]; do sleep 2; done
  fi
fi
if [ "$bootstrap_only" = yes ]; then
  echo "modularca: configured; nothing more to do"
  exit 0
fi
exec ./ModularCA.API "$@"
