tshark -R "tcp.port == 502" -r ~/Bureau/data/scadaCops/normal/capture_schneider_20150903_normal.pcapng \
-T fields -E separator=, -t r -E header=y  \
-e frame.number -e frame.time_relative -e frame.time_delta -e frame.len \
-e ip.proto -e ip.version -e ip.src -e eth.src -e ip.dst -e eth.dst \
-e mbtcp.modbus.unit_id -e tcp.srcport -e tcp.dstport -e mbtcp.prot_id \
-e mbtcp.trans_id -e mbtcp.len -e mbtcp.modbus.func_code -e mbtcp.modbus.reference_num \
-e mbtcp.modbus.word_cnt -e mbtcp.modbus.data > normal.data \
