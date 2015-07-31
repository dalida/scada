#!/bin/bash
#
# processScada.sh
#
# MALIPHOL
# 7/2015
#
# Process MODBUS/TCP packet capture.
#
# Currently, this process combines various tools:
#    - bash: script to drive the whole process, as well as
#        do some data munging
#    - tshark: extracts various fields from pcap file
#    - c: merge transactions
#    - R: calculate stats and create json
#

# VARIABLES #

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
#IMP=1

# FUNCTIONS #

function extract_pcap() {

	if [ -f "$PCAP_FILE" ]
	then
		printf "\npcap file: $PCAP_FILE\n"

        # extract MODBUS
		printf "\nExtracting from pcap file...\n"
		tshark -R "tcp.port == 502" -r $PCAP_FILE -T fields -E separator=, -t r -E header=y -e frame.number -e frame.time_relative -e frame.time_delta -e frame.len -e ip.proto -e ip.version -e ip.src -e eth.src -e ip.dst -e eth.dst -e mbtcp.modbus.unit_id -e tcp.srcport -e tcp.dstport -e mbtcp.prot_id -e mbtcp.trans_id  -e mbtcp.len -e mbtcp.modbus.func_code -e mbtcp.modbus.reference_num -e mbtcp.modbus.word_cnt -e mbtcp.modbus.data > $DATA_FILE
	
		if [ -f "$DATA_FILE" ]
		then
			printf "\nCreated data file: $DATA_FILE\n"
		else
			printf "\nError extract_pcap: no data file extracted from $PCAP_FILE.\n"
			exit 1

		fi
	else
		printf "\nError extract_pcap: No packet capture file: $PCAP_FILE"
		exit 1
	fi
} # end extract_pcap

function scrub_data() {

	printf "\nScrubbing data and processing transformations...\n"

    # save headers for later, they'll get re-added
	sed '2,$d' $DATA_FILE > $HEADER

    # cleanup data
	sed -i '/,,,,,$/d' $DATA_FILE

    # remove header for processing
	sed '1,2d' $DATA_FILE > ${DATA_FILE}.tmp

} # end scrub_data

function merge() {

    # this is where the merging happens
	./processMerge ${DATA_FILE}.tmp $OUT_FILE > $LOG_FILE

} # end merge

function create_import_file() {

	printf "\nCreating import file...\n"

    # no modbus data in request
	sed -i 's/mbtcp\.modbus\.data$//' $HEADER

	EXTRA_HEADERS="frame.second,respFrameNumber,respTimeRel,respTimeDelta,respLen,respIpSrc,respEthSrc,respIpDest,respEthDst,respUnitId,respSrcPort,respDstPort,respProtId,respTransId,respMbtcpLen,respFuncCode,mbtcpModbusData,respSecond,d"

    # re-add extended header
	sed -i "s/$/${EXTRA_HEADERS}/" $HEADER

	cat $HEADER > $IMP_FILE
	cat $OUT_FILE >> $IMP_FILE

	if [ -f "$IMP_FILE" ]
	then
		printf "\nCreated file $IMP_FILE\n"
	else
		printf "\nError create_import_file: no import file created.\n"
		exit 1
	fi

} # end create_import_file

# Calculates and generates JSON stas and whitelist databases from
# files previously generated- data/sew.dat, data/sew.imp
function gen_configs() {

	printf "\nCalculating stats and creating JSON config files...\n"
	r/createJS.r

	if [ $? -ne 0 ]
	then
		printf "\ngen_configs: Error generating config files.\n"
	fi

} # end gen_configs

function import_db() {

	# fix headers for db import
	sed -i '1s/\./_/g' $IMP_FILE
 
    # headers for mongodb
	EXTRA_HEADERS=",frame_second, resp_frame_num,resp_time_rel,resp_time_delta,resp_len,resp_ip_src,resp_eth_src,resp_ip_dest,resp_eth_dst,resp_unit_id,resp_src_port,resp_dst_port,resp_prot_id,resp_trans_id,resp_mbtcp_len,resp_func_code,mbtcp_modbus_data,resp_second, d"

	#cat $IMP_FILE >> $EXTRA_HEADERS
	#mv $EXTRA_HEADERS $IMP_FILE

	printf "\nImporting into database...\n"
    # TODO: should be changed to run as superuser, ie, remove sudo
	# mysqldb import
    #sudo mysqlimport --fields-terminated-by=, --delete --user=$DB_USER --password=$DB_PASS --local $DB $OUT_FILE

	# mongodb import
	printf "db.packets.remove({})" | mongo scadadb
	mongoimport -d $MONGO_DB -c packets --type csv --file $IMP_FILE --headerline

} # end import_db

function cleanup() {

	printf "\nCleaning up...\n"
	rm $HEADER
	rm ${DATA_FILE}
	rm ${DATA_FILE}.tmp
	rm ${OUT_FILE}
	rm ${IMP_FILE}

} # end cleanup

# MAIN #

printf "\nBegin process...\n"

extract_pcap

scrub_data

merge

create_import_file

gen_configs

if [ $IMP -eq 1 ]
then
    # import into db
	import_db
fi

cleanup

printf "\nDone!\n\n"
