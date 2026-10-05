#!/bin/sh
# The image's entrypoint, for every container the pod runs from it.
#
# First start: no config.yaml yet. With a bootstrap.yaml in the config volume, run the headless
# bootstrap from it and setup-database.yaml. The bootstrap prints the initial administrator
# password once; the container's log is where it lands, so read it there and change it at first
# sign-in. With no bootstrap.yaml, start the setup wizard instead: it prints a one-time token to
# the log, and stops the process twice on the way through (after the database step and at the
# end), so the container needs a restart policy. Every later start just runs.
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
  if [ "$wants_bootstrap" = yes ] && [ ! -f config/bootstrap.yaml ] && [ "$bootstrap_only" = no ]; then
    echo "modularca: not configured and no bootstrap.yaml; starting the setup wizard"
    exec ./ModularCA.API "$@"
  elif [ "$wants_bootstrap" = yes ]; then
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
