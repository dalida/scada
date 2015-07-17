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
#STEM="sew"
PCAP_FILE="${STEM}.pcap"
DATA_FILE="${STEM}.dat"
OUT_FILE="${STEM}.out"
IMP_FILE="${STEM}.imp"
HEADER="header.txt"
MONGO_DB="scadadb"

echo "\nBegin process...\n"

if [ -f "$PCAP_FILE" ]
then

	echo "pcap file: "$PCAP_FILE

    # extract MODBUS
	echo "\nExtracting from pcap file...\n"
	tshark -r $PCAP_FILE -T fields -E separator=, -t r -E header=y -e frame.number -e frame.time_relative -e frame.time_delta -e frame.len -e ip.proto -e ip.version -e ip.src -e eth.src -e ip.dst -e eth.dst -e mbtcp.modbus.unit_id -e tcp.srcport -e tcp.dstport -e mbtcp.prot_id -e mbtcp.trans_id  -e mbtcp.len -e mbtcp.modbus.func_code -e mbtcp.modbus.reference_num -e mbtcp.modbus.word_cnt -e mbtcp.modbus.data > $DATA_FILE
	
	if [ -f "$DATA_FILE" ]
	then

		echo "Created data file: "$DATA_FILE
		echo "\nScrubbing data and processing transformations...\n"

        # modify header (keep for mongodb)
        #sed -i '1,2d' $DATA_FILE
        sed '2,$d' $DATA_FILE > $HEADER
		sed -i 's/,mbtcp.modbus.data//' $HEADER
		sed -i 's/\./_/g' $HEADER

		EXTRA_HEADERS=",respFrNumber,respTimeRel,respTimeDelta,respLen,respIpSrc,respEthSrc,respIpDest,respEthDest,respUnitId,respSrcport,respDstPort,respProtId,respTransId,respMbtcpLen,respFuncCode,mbtcpModbusData,d"
		#sed -i 's/$/,d/' $HEADER
		sed -i "s/$/${EXTRA_HEADERS}/" $HEADER

		# remove header for processing
		sed -i '1,2d' $DATA_FILE

        # cleanup data
		sed -i '/,,,,,$/d' ${DATA_FILE}

        # convert resp.data from hex to decimal -- moved to processCSV
        #awk -F"," 'BEGIN{ OFS="," }{split($18,a,":");  $19=strtonum("0x"a[1]a[2]) ; print }' ${DATA_FILE} > ${OUT_FILE}.tmp
        #awk -F, '{$1="" FS $1;}1' OFS=, ${OUT_FILE}.tmp > ${OUT_FILE}

        # comment first line -- changed tshark:header=n
        #sed '1 s/^/--/' ${OUT_FILE}.tmp > ${OUT_FILE}  

		./processCSV $DATA_FILE $OUT_FILE > log.`date '+%Y%m%d%H%M'`.out

		# re-add header
		cat $HEADER > $IMP_FILE
		cat $OUT_FILE >> $IMP_FILE

		if [ -f "$IMP_FILE" ]
		then

		echo "Created file "$IMP_FILE

		echo "\nImporting into database...\n"
        # TODO: should be changed to run as superuser, ie, remove sudo
		# mysqldb import
        #sudo mysqlimport --fields-terminated-by=, --delete --user=$DB_USER --password=$DB_PASS --local $DB $OUT_FILE
		# mongodb import
		#echo -e "db.packets.remove({})" | mongo $MONGO_DB
		echo "db.packets.remove({})" | mongo scadadb
		mongoimport -d $MONGO_DB -c packets --type csv --file $IMP_FILE --headerline

        # cleanup
        #rm *.tmp

		else
			
			echo "$OUT_FILE not created and imported."

		fi

	else

		echo "$DATA_FILE not extracted from $PCAP_FILE."

	fi  # end DATA_FILE exists
	
else

	echo "$PCAP_FILE does not exist."

fi # end PCAP_FILE exists

echo "\nDone!\n"

