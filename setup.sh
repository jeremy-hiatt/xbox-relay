#!/bin/bash

PYTHON=$(which python3.7)

BASEDIR=$( cd "$(dirname "$0")" ; pwd -P )

if [[ "${PYTHON}" = "${BASEDIR}"* ]]
then
  echo "Already activated; don't need to create venv"
else
  "${PYTHON}" -m venv "${BASEDIR}/env"
fi

"${BASEDIR}/env/bin/pip" install -r "${BASEDIR}/requirements.txt"
