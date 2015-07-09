#!/bin/sh
#
# processScada.sh
#
# MALIPHOL
# 7/2015
#
# Process and load of MODBUS/TCP packet capture.
#

DB="scada"
DB_USER="scada"
DB_PASS="scada"
STEM="mb2k"
PCAP_FILE="${STEM}.pcap"
DATA_FILE="${STEM}.dat"
TMP_FILE="${STEM}.tmp"
OUT_FILE="NormalPackets.dat"

echo "Begin process...\n"

echo "pcap file: "$PCAP_FILE
echo "\n"

# extract MODBUS
echo "Extracting from pcap file...\n"
tshark -r $PCAP_FILE -T fields -E separator=, -t r -E header=y -e frame.number -e frame.time_relative -e frame.time_delta_displayed -e frame.len -e ip.proto -e ip.version -e ip.src -e ip.dst -e mbtcp.modbus.unit_id -e tcp.srcport -e tcp.dstport -e mbtcp.prot_id -e mbtcp.trans_id  -e mbtcp.len -e mbtcp.modbus.func_code -e mbtcp.modbus.reference_num -e mbtcp.modbus.word_cnt -e mbtcp.modbus.data > $DATA_FILE

echo "Created data file: "$DATA_FILE
echo "\n"

echo "Processing data scrubbing and transformations...\n"
# comment first line
# remove header line
sed -i '1d' $DATA_FILE
#mv ${DATA_FILE}.tmp $DATA_FILE

# remove empty modbus data
#sed '/,,,,,$/d' ${DATA_FILE}.tmp > ${DATA_FILE}.tmp1
sed -i '/,,,,,$/d' ${DATA_FILE}
#mv ${DATA_FILE}.tmp $DATA_FILE

# convert resp.data from hex to decimal
awk -F"," 'BEGIN{ OFS="," }{split($18,a,":");  $19=strtonum("0x"a[1]a[2]) ; print }' ${DATA_FILE} > ${OUT_FILE}.tmp
awk -F, '{$1="" FS $1;}1' OFS=, ${OUT_FILE}.tmp > ${OUT_FILE}

# comment first line
#sed '1 s/^/--/' ${OUT_FILE}.tmp > ${OUT_FILE}  

echo "Created file "$OUT_FILE

echo "\nImporting into database...\n"
# TODO: should be changed to run as superuser, ie, remove sudo
sudo mysqlimport --fields-terminated-by=, --delete --user=$DB_USER --password=$DB_PASS --local $DB $OUT_FILE

# cleanup
#rm *.tmp

echo "Done!\n"

