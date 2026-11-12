#!/bin/sh
# The image's entrypoint, for every container the pod runs from it.
#
# First start: no config.yaml yet. With a bootstrap.yaml in the config volume, run the headless
# bootstrap from it and setup-database.yaml. The bootstrap never prints the initial administrator's
# password, because this container's log is the journal under Quadlet: with
# Administration.ClaimTokenSha256 in bootstrap.yaml the account is claimed with the matching token
# at /claim; without it the generated password is left in config/initial-admin-password, readable
# by the image's account only. Read it, sign in, change it when asked, and the file is deleted.
# With no bootstrap.yaml, start the setup wizard instead: it prints a one-time token to
# the log, and stops the process twice on the way through (after the database step and at the
# end), so the container needs a restart policy. Every later start just runs.
#
# Only a process that will hold the control role may bootstrap. Two processes racing to create
# the keystore in one directory is the thing this check exists to prevent: a signer or an ingress
# waits for its configuration to be there instead. A signer run with --signer-dir <dir> reads
# <dir>/signer.yaml and <dir>/db.yaml and nothing under config/, which in the pod it does not
# even mount, so those are the files it waits for; the pod's init containers fill them. The
# identity init containers run the binary directly and pass their own role.
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
signer_dir=
for arg in "$@"; do
  if [ "${expect_role:-}" = yes ]; then
    case "$arg" in *signer*|*ingress*) wants_bootstrap=no ;; esac
    expect_role=
    continue
  fi
  if [ "${expect_signer_dir:-}" = yes ]; then
    signer_dir=$arg
    expect_signer_dir=
    continue
  fi
  case "$arg" in
    --role)        expect_role=yes ;;
    --role=*)      case "${arg#--role=}" in *signer*|*ingress*) wants_bootstrap=no ;; esac ;;
    --signer-dir)  expect_signer_dir=yes ;;
  esac
done

# A signer with its own directory: configured when that directory holds its settings.
if [ -n "$signer_dir" ] && [ "$bootstrap_only" = no ]; then
  if [ ! -f "$signer_dir/signer.yaml" ] || [ ! -f "$signer_dir/db.yaml" ]; then
    echo "modularca: waiting for the signer's directory $signer_dir to hold signer.yaml and db.yaml"
    until [ -f "$signer_dir/signer.yaml" ] && [ -f "$signer_dir/db.yaml" ]; do sleep 2; done
  fi
  exec ./ModularCA.API "$@"
fi

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
