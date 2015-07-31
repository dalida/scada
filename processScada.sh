#!/bin/sh
#
# processScada.sh
#
# MALIPHOL
# 7/2015
#
# Process and load of MODBUS/TCP packet capture.
#
# Currently, this process combines various tools:
#    - bash: script to drive the whole process, as well as
#        do some data munging
#    - tshark: extracts various fields from pcap file
#    - c: merge transactions
#    - R: calculate stats and create json
#

STEM="sew"

PCAP_FILE="data/${STEM}.pcap"
DATA_FILE="data/${STEM}.dat"
OUT_FILE="data/${STEM}.out"
IMP_FILE="data/${STEM}.imp"
LOG_FILE="log/log.`date '+%Y%m%d%H%M'`.out"
HEADER="header.txt"

# db credientials
MONGO_DB="scadadb"
DB="scada"
DB_USER="scada"
DB_PASS="scada"
IMP=0

echo "\nBegin process...\n"

if [ -f "$PCAP_FILE" ]
then

	echo "pcap file: "$PCAP_FILE

    # extract MODBUS
	echo "\nExtracting from pcap file...\n"
	tshark -R "tcp.port == 502" -r $PCAP_FILE -T fields -E separator=, -t r -E header=y -e frame.number -e frame.time_relative -e frame.time_delta -e frame.len -e ip.proto -e ip.version -e ip.src -e eth.src -e ip.dst -e eth.dst -e mbtcp.modbus.unit_id -e tcp.srcport -e tcp.dstport -e mbtcp.prot_id -e mbtcp.trans_id  -e mbtcp.len -e mbtcp.modbus.func_code -e mbtcp.modbus.reference_num -e mbtcp.modbus.word_cnt -e mbtcp.modbus.data > $DATA_FILE
	
	if [ -f "$DATA_FILE" ]
	then

		echo "Created data file: "$DATA_FILE
		echo "\nScrubbing data and processing transformations...\n"

		# remove header
		# save headers for later
        sed '2,$d' $DATA_FILE > $HEADER

        # cleanup data
		sed -i '/,,,,,$/d' ${DATA_FILE}

		# remove header for processing
		sed '1,2d' $DATA_FILE > ${DATA_FILE}.tmp

		# this is where the merging happens
		./processCSV ${DATA_FILE}.tmp $OUT_FILE > $LOG_FILE

		# re-add extended header to mergedSewDT
		# no modbus data in request
		sed -i 's/mbtcp\.modbus\.data$//' $HEADER

		EXTRA_HEADERS="frame.second,respFrameNumber,respTimeRel,respTimeDelta,respLen,respIpSrc,respEthSrc,respIpDest,respEthDst,respUnitId,respSrcPort,respDstPort,respProtId,respTransId,respMbtcpLen,respFuncCode,mbtcpModbusData,respSecond,d"
		sed -i "s/$/${EXTRA_HEADERS}/" $HEADER

		cat $HEADER > $IMP_FILE
		cat $OUT_FILE >> $IMP_FILE

        # modify header for mongodb because it doesn't like periods
		#sed -i 's/,mbtcp.modbus.data//' $HEADER
		#sed -i 's/\./_/g' $HEADER

		# headers for mongodb
		#EXTRA_HEADERS=",frame_second, resp_frame_num,resp_time_rel,resp_time_delta,resp_len,resp_ip_src,resp_eth_src,resp_ip_dest,resp_eth_dst,resp_unit_id,resp_src_port,resp_dst_port,resp_prot_id,resp_trans_id,resp_mbtcp_len,resp_func_code,mbtcp_modbus_data,resp_second, d"

        # convert resp.data from hex to decimal -- moved to processCSV
        #awk -F"," 'BEGIN{ OFS="," }{split($18,a,":");  $19=strtonum("0x"a[1]a[2]) ; print }' ${DATA_FILE} > ${OUT_FILE}.tmp
        #awk -F, '{$1="" FS $1;}1' OFS=, ${OUT_FILE}.tmp > ${OUT_FILE}

        # comment first line -- changed tshark:header=n
        #sed '1 s/^/--/' ${OUT_FILE}.tmp > ${OUT_FILE}  

		# calculate stats and create JSON 
		echo "Calculating stats and creating JSON config files...\n"
		r/createJS.r

		# import into db of choice
		if [ $IMP == 1 && -f "$IMP_FILE" ]
		then

			echo "Created file "$IMP_FILE

			echo "\nImporting into database...\n"
            # TODO: should be changed to run as superuser, ie, remove sudo
		    # mysqldb import
            #sudo mysqlimport --fields-terminated-by=, --delete --user=$DB_USER --password=$DB_PASS --local $DB $OUT_FILE

		    # mongodb import
			echo "db.packets.remove({})" | mongo scadadb
			mongoimport -d $MONGO_DB -c packets --type csv --file $IMP_FILE --headerline

            # cleanup
			#echo "\nCleaning up..."
			rm $HEADER
			#rm ${DATA_FILE}
			rm ${DATA_FILE}.tmp
			rm ${OUT_FILE}
			#rm ${IMP_FILE}

		else
			
			echo "$IMP_FILE not created and imported."

		fi

	else

		echo "$DATA_FILE not extracted from $PCAP_FILE."

	fi  # end DATA_FILE exists
	
else

	echo "$PCAP_FILE does not exist."

fi # end PCAP_FILE exists

echo "\nDone!\n"

