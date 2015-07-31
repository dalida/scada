#!/usr/local/bin/r

library(data.table)

# import datafile
datafile <- "~/scada/data/sew.dat"

sewModbusDT <- as.data.table(
  read.csv(datafile, header=TRUE,
           stringsAsFactors=T
           ))

# import merged transactions
mergedfile <- "~/scada/data/sew.imp"

mergedSewDT <- as.data.table(
  read.csv(mergedfile, header=TRUE,
           stringsAsFactors=T
  ))

#### GENERATE WHITE LIST ####
# Sources
# srcs <- sewModbusDT[,.(count=.N), by=.(ip.src)]
srcs  <- unique(sewModbusDT, by=c("ip.src"))[,.(ip.src)]
srcs
txt1 <- sprintf('"IP_SRC" : [%s]',
                paste0(
                  with(srcs,
                       sprintf('"%s"',
                               ip.src)),
                  collapse = ","))

# Destinations
# dst <- sewModbusDT[,.(count=.N), by=.(ip.dst)]
dst <- unique(sewModbusDT, by=c("ip.dst"))[,.(ip.dst)]
dst
txt2 <- sprintf('"IP_DST" : [%s]',
                paste0(
                  with(dst,
                       sprintf('"%s"',
                               ip.dst)),
                  collapse = ","))

# Destination / UnitID
# du <- sewModbusDT[,.(ip.dst.unit_id = paste(ip.dst, mbtcp.modbus.unit_id, sep="/")),
#                   by=.(ip.dst, mbtcp.modbus.unit_id)]
du <- unique(sewModbusDT,
             by=c("ip.dst",
                  "mbtcp.modbus.unit_id"))[
                    ,.(IP_MODBUS_UNIT_ID = paste(ip.dst,
                                                 mbtcp.modbus.unit_id, sep="/"),
                       ip.dst,
                       mbtcp.modbus.unit_id)]

txt3 <- sprintf('"IP_MODBUS_UNIT_ID" : [\n%s\n]',
                paste0(
                  with(du,
                       sprintf('  "%s" : {\n   "IP_ADDR" : "%s",\n   "UNIT_ID" : "%s "\n  }',
                               IP_MODBUS_UNIT_ID, ip.dst, mbtcp.modbus.unit_id)),
                  collapse = ",\n"))

# Source / MAC Address
#smac <- sewModbusDT[,.(count=.N), by=.(ip.src, eth.src)]
smac <- unique(sewModbusDT,
               by=c("ip.src", "eth.src"))[
                 ,.(IP_ADDR_MAC_ADDR = paste(ip.src, eth.src, sep="/"),
                    ip.src,
                    eth.src)]

txt4 <- sprintf('"IP_ADDR_MAC_ADDR" : [\n%s\n]',
                paste0(
                  with(smac,
                       sprintf('  "%s" : {\n    "IP_ADDR" : "%s",\n   "MAC_ADDR" : "%s "\n  }',
                               IP_ADDR_MAC_ADDR, ip.src, eth.src)),
                  collapse = ",\n"))

# Source / Function Code
sfunc <- sewModbusDT[,.(IP_ADDR_MOD_FUNC = paste(ip.src, mbtcp.modbus.func_code, sep="/"))
                     , by=.(ip.src, mbtcp.modbus.func_code)][
                       ,.(IP_ADDR_MOD_FUNC, ip.src,
                          mbtcp.modbus.func_code)]

txt5 <- sprintf('"IP_ADDR_MODBUS_FUNC" : [\n%s\n]',
                paste0(
                  with(sfunc,
                       sprintf('  "%s" : {\n    "IP_ADDR" : "%s",\n   "MODBUS_FUNCTION" : "%s "\n  }',
                               IP_ADDR_MOD_FUNC, ip.src, mbtcp.modbus.func_code)),
                  collapse = ",\n"))

# Source / Function Code
sfuncRef <- mergedSewDT[,.(IP_ADDR_MOD_FUNC_REF = paste(ip.src, mbtcp.modbus.func_code,
                                                        mbtcp.modbus.reference_num, sep="/"))
                        , by=.(ip.src, mbtcp.modbus.func_code, mbtcp.modbus.reference_num)][
                          ,.(IP_ADDR_MOD_FUNC_REF,
                             ip.src,
                             mbtcp.modbus.func_code,
                             mbtcp.modbus.reference_num)][order(mbtcp.modbus.reference_num)]

txt6 <- sprintf('"IP_ADDR_MODBUS_FUNC_REF" : [\n%s\n]',
                paste0(
                  with(sfuncRef,
                       sprintf('  "%s" : {\n    "IP_SRC" : "%s",\n     "MODBUS_FUNCTION" : "%s ",\n    "MODBUS_REFERENCE" : "%s "\n  }',
                               IP_ADDR_MOD_FUNC_REF, ip.src, mbtcp.modbus.func_code, mbtcp.modbus.reference_num)),
                  collapse = ",\n"))

whitelist <- sprintf('{\n%s\n}',
                     paste(txt1, txt2, txt3, txt4, txt5, txt6, sep=",\n")
)
write(whitelist, file="r/whitelist.db")
rm(txt1, txt2, txt3, txt4, txt5, txt6, srcs, dst, du, smac, sfunc, sfuncRef, whitelist)

# Packet Analysis

## STATS
### Average frequency of packets per second
avgPkt <- mergedSewDT[,.(frequency=.N),by=frame.second][,mean(frequency)]

### Frequency per second, per source/dest ip and function code
srcFuncFreq <- mergedSewDT[,.(frequency=.N),
                           by =.(ip.src, ip.dst, mbtcp.modbus.func_code,
                                 frame.second)][
                                   order(ip.src, ip.dst, mbtcp.modbus.func_code,
                                         frame.second)][,.(avgFrequencySec=mean(frequency)),
                                                        by=.(ip.src, ip.dst, mbtcp.modbus.func_code)]

txt1 <- sprintf('"SOURCE_DEST_FUNCTION_FREQUENCY" : [\n%s\n]',
                paste0(
                  with(srcFuncFreq,
                       sprintf('  "%s" : {\n    "IP_SRC" : "%s",\n    "IP_DST" : "%s",\n    "MODBUS_FUNCTION" : "%s ",\n    "FREQUENCY" : "%f "\n  }',
                               paste(ip.src, ip.dst, mbtcp.modbus.func_code, sep="/"),
                               ip.src, ip.dst, mbtcp.modbus.func_code,
                               avgFrequencySec)),
                  collapse = ",\n"))

# Frequency per second, per source/dest ip, function code, and reference num
srcFuncRefFreq <- mergedSewDT[,.(frequency=.N),
                              by =.(ip.src, ip.dst, mbtcp.modbus.func_code, mbtcp.modbus.reference_num,
                                    frame.second)][
                                      order(ip.src, ip.dst, mbtcp.modbus.func_code, mbtcp.modbus.reference_num,
                                            frame.second)][,.(avgFrequncySec=mean(frequency)),
                                                           by=.(ip.src, ip.dst, mbtcp.modbus.func_code,
                                                                mbtcp.modbus.reference_num)]

txt2 <- sprintf('"SOURCE_DEST_FUNCTION_REFERENCE_FREQUENCY" : [\n%s\n]',
                paste0(
                  with(srcFuncRefFreq,
                       sprintf('  "%s" : {\n    "IP_SRC" : "%s",\n    "IP_DST" : "%s",\n    "MODBUS_FUNCTION" : "%s ",\n    "MODBUS_REFERENCE" : "%s ",\n    "FREQUENCY" : "%f "\n  }',
                               paste(ip.src, ip.dst, mbtcp.modbus.func_code, mbtcp.modbus.reference_num, sep="/"),
                               ip.src, ip.dst, mbtcp.modbus.func_code,
                               mbtcp.modbus.reference_num,
                               avgFrequncySec)),
                  collapse = ",\n"))

modbusStats <- mergedSewDT[,.(frequency=.N, d.min=min(d), d.mean=mean(d, na.rm=T),
                              d.sd=sd(d, na.rm=T), d.max=max(d)
), by =.(mbtcp.modbus.func_code, mbtcp.modbus.reference_num)][
  order(mbtcp.modbus.func_code, mbtcp.modbus.reference_num)]

txt3 <- sprintf('"MODBUS_FUNCTION_REFERENCE_DATA_STATS" : [\n%s\n]',
                paste0(
                  with(modbusStats,
                       sprintf('  "%s" : {\n    "MODBUS_FUNCTION" : "%s",\n    "MODBUS_REFERENCE" : "%s",\n    "D_MIN" : "%.2f ",\n    "D_MEAN" : "%.2f ",\n    "D_STD_DEV" : "%.2f ",\n    "D_MAX" : "%.2f "\n  }',
                               paste(mbtcp.modbus.func_code, mbtcp.modbus.reference_num, sep="/"),
                               mbtcp.modbus.func_code,
                               mbtcp.modbus.reference_num,
                               d.min, d.mean, d.sd, d.max)),
                  collapse = ",\n"))

stats <- sprintf('{\n%s\n}',
                 paste(txt1, txt2, txt3, sep=",\n")
)
write(stats, file="r/stats.db")
rm(txt1, txt2, txt3,srcFuncFreq, srcFuncRefFreq, avgPkt, stats)
rm(modbusStats, datafile, mergedfile, sewModbusDT, mergedSewDT)
