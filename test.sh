#!/bin/sh


DATA_FILE="100k.dat"

echo "${DATA_FILE}\n"


START=$(date +%s)





END=$(date +%s)
DIFF=$(( $END - $START ))
echo "Time to process... ${DIFF}\n"
