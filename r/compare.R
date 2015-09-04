#!/bin/local/usr/r
  
library(data.table)


#####################################################################################

#Normal data

#####################################################################################

datafile <- "~/scada/normal.data"

normalModbusDT <- as.data.table(
  read.csv(datafile, header=TRUE,
           stringsAsFactors=T,
           colClass=c(ip.proto="factor", ip.version="factor", ip.src="factor",
                      ip.dst="factor", eth.src="factor", eth.dst="factor",
                      mbtcp.modbus.unit_id="factor",
                      tcp.srcport="factor", tcp.dstport="factor",
                      mbtcp.modbus.func_code="factor",
                      mbtcp.modbus.reference_num="factor",
                      mbtcp.prot_id="factor")))

# cleanup

normalModbusDT <- normalModbusDT[!(is.na(frame.number))]
normalModbusDT <- normalModbusDT[!(is.na(mbtcp.modbus.unit_id))]
normalModbusDT <- normalModbusDT[!(is.na(mbtcp.trans_id))]
normalModbusDT <- normalModbusDT[!(is.na(mbtcp.modbus.reference_num))]

save(normalModbusDT, file="normal.Rda")

# import datafile
load("normal.Rda")

normalModbusDT$frame.second <- floor(normalModbusDT$frame.time_relative)


# Sources
srcs  <- unique(normalModbusDT, by=c("ip.src"))[,.(ip.src)]


# Destinations
dst <- unique(normalModbusDT, by=c("ip.dst"))[,.(ip.dst)]


# Destination / UnitID
du <- unique(normalModbusDT,
             by=c("ip.dst",
                  "mbtcp.modbus.unit_id"))[
                    ,.(IP_DST_MODBUS_UNIT_ID = paste(ip.dst,
                                                     mbtcp.modbus.unit_id, sep="/"),
                       ip.dst,
                       mbtcp.modbus.unit_id)]


# Source / MAC Address
smac <- unique(normalModbusDT,
               by=c("ip.src", "eth.src"))[
                 ,.(IP_SRC_MAC_ADDR = paste(ip.src, eth.src, sep="/"),
                    ip.src,
                    eth.src)]


# Source / Function Code
sfunc <- normalModbusDT[,.(IP_SRC_MOD_FUNC = paste(ip.src, mbtcp.modbus.func_code, sep="/"))
                     , by=.(ip.src, mbtcp.modbus.func_code)][
                       ,.(IP_SRC_MOD_FUNC, ip.src,
                          mbtcp.modbus.func_code)]


#############################################################################################################

reqs <- normalModbusDT[mbtcp.modbus.reference_num != '']
resp <- normalModbusDT[is.na(mbtcp.modbus.reference_num)]

#############################################################################################################

# Source / Function Code

sfuncRef <- reqs[,.(IP_SRC_MOD_FUNC_REF = paste(ip.src, mbtcp.modbus.func_code,
                                                mbtcp.modbus.reference_num, sep="/"))
                 , by=.(ip.src, mbtcp.modbus.func_code, mbtcp.modbus.reference_num)][
                   ,.(IP_SRC_MOD_FUNC_REF,
                      ip.src,
                      mbtcp.modbus.func_code,
                      mbtcp.modbus.reference_num)][order(mbtcp.modbus.reference_num)]

#rm(txt1, txt2, txt3, txt4, txt5, txt6, srcs, dst, du, smac, sfunc, sfuncRef, whitelist)

# Packet Analysis

# STATS
# Average frequency of packets per second
avgPkt <- normalModbusDT[,.(frequency=.N),by=frame.second][,mean(frequency)]

# Frequency per second, per source/edst ip and function code
srcFuncFreq <- normalModbusDT[,.(frequency=.N),
                           by =.(ip.src, ip.dst, mbtcp.modbus.func_code,
                                 frame.second)][
                                   order(ip.src, ip.dst, mbtcp.modbus.func_code,
                                         frame.second)][,.(avgFrequencySec=mean(frequency)),
                                                        by=.(ip.src, ip.dst, mbtcp.modbus.func_code)]

# Frequency per second, per source/dest ip, function code, and reference num
srcFuncRefFreq <- reqs[,.(frequency=.N),
                       by =.(ip.src, ip.dst, mbtcp.modbus.func_code, mbtcp.modbus.reference_num,
                             frame.second)][
                               order(ip.src, ip.dst, mbtcp.modbus.func_code, mbtcp.modbus.reference_num,
                                     frame.second)][,.(avgFrequncySec=mean(frequency)),
                                                    by=.(ip.src, ip.dst, mbtcp.modbus.func_code,
                                                         mbtcp.modbus.reference_num)]


# modbusStats <- mergednormalDT[,.(frequency=.N, d.min=min(d), d.mean=mean(d, na.rm=T),
#                               d.sd=sd(d, na.rm=T), d.max=max(d)
# ), by =.(mbtcp.modbus.func_code, mbtcp.modbus.reference_num)][
#   order(mbtcp.modbus.func_code, mbtcp.modbus.reference_num)]

#rm(reqs, reps)
#rm(txt1, txt2, txt3,srcFuncFreq, srcFuncRefFreq, avgPkt, stats)
#rm(modbusStats, datafile, mergedfile, normalModbusDT, mergednormalDT)



#####################################################################################

Attacks injected

#####################################################################################


load("attack.Rda")

attackModbusDT$frame.second <- floor(attackModbusDT$frame.time_relative)

attackSrcs  <- unique(attackModbusDT, by=c("ip.src"))[,.(ip.src)]

attackDst <- unique(attackModbusDT, by=c("ip.dst"))[,.(ip.dst)]

attackDu <- unique(attackModbusDT,
             by=c("ip.dst",
                  "mbtcp.modbus.unit_id"))[
                    ,.(IP_DST_MODBUS_UNIT_ID = paste(ip.dst,
                                                     mbtcp.modbus.unit_id, sep="/"),
                       ip.dst,
                       mbtcp.modbus.unit_id)]

attackSmac <- unique(attackModbusDT,
               by=c("ip.src", "eth.src"))[
                 ,.(IP_SRC_MAC_ADDR = paste(ip.src, eth.src, sep="/"),
                    ip.src,
                    eth.src)]

attackSfunc <- attackModbusDT[,.(IP_SRC_MOD_FUNC = paste(ip.src, mbtcp.modbus.func_code, sep="/"))
                     , by=.(ip.src, mbtcp.modbus.func_code)][
                       ,.(IP_SRC_MOD_FUNC, ip.src,
                          mbtcp.modbus.func_code)]


#############################################################################################################

attackReqs <- attackModbusDT[mbtcp.modbus.reference_num != '']
attackResp <- attackModbusDT[is.na(mbtcp.modbus.reference_num)]

#############################################################################################################


attackSfuncRef <- attackReqs[,.(IP_SRC_MOD_FUNC_REF = paste(ip.src, mbtcp.modbus.func_code,
                                                mbtcp.modbus.reference_num, sep="/"))
                 , by=.(ip.src, mbtcp.modbus.func_code, mbtcp.modbus.reference_num)][
                   ,.(IP_SRC_MOD_FUNC_REF,
                      ip.src,
                      mbtcp.modbus.func_code,
                      mbtcp.modbus.reference_num)][order(mbtcp.modbus.reference_num)]

attackAvgPkt <- attackModbusDT[,.(frequency=.N),by=frame.second][,mean(frequency)]

# Frequency per second, per source/dest ip and function code
attackSrcFuncFreq <- attackModbusDT[,.(frequency=.N),
                           by =.(ip.src, ip.dst, mbtcp.modbus.func_code,
                                 frame.second)][
                                   order(ip.src, ip.dst, mbtcp.modbus.func_code,
                                         frame.second)][,.(avgFrequencySec=mean(frequency)),
                                                        by=.(ip.src, ip.dst, mbtcp.modbus.func_code)]

# Frequency per second, per source/dest ip, function code, and reference num
attackSrcFuncRefFreq <- attackReqs[,.(frequency=.N),
                       by =.(ip.src, ip.dst, mbtcp.modbus.func_code, mbtcp.modbus.reference_num,
                             frame.second)][
                               order(ip.src, ip.dst, mbtcp.modbus.func_code, mbtcp.modbus.reference_num,
                                     frame.second)][,.(avgFrequncySec=mean(frequency)),
                                                    by=.(ip.src, ip.dst, mbtcp.modbus.func_code,
                                                         mbtcp.modbus.reference_num)]

#############################################################################################################

# Comparison

#############################################################################################################

setkey(attackSrcs, ip.src)
badSrcs <- attackSrcs[!srcs]
badSrcs

setkey(attackDst, ip.dst)
badDsts <- attackDst[!dst]
badDsts

setkey(attackDu, IP_DST_MODBUS_UNIT_ID)
badDus <- attackDu[!du]
badDus

setkey(attackSmac, IP_SRC_MAC_ADDR)
badSmac <- attackSmac[!smac]
badSmac

setkey(attackSfunc, IP_SRC_MOD_FUNC)
badSfunc <- attackSfunc[!sfunc]
badSfunc

setkey(attackSfuncRef, IP_SRC_MOD_FUNC_REF)
badSfuncRef <- attackSfuncRef[!sfuncRef]
badSfuncRef

avgPkt - attackAvgPkt

setkey(attackSrcFuncFreq, ip.src, ip.dst, mbtcp.modbus.func_code)
badSrcFuncFreq <- attackSrcFuncFreq[!srcFuncFreq]
badSrcFuncFreq

mergedSrcFuncFreq <- merge(srcFuncFreq,attackSrcFuncFreq, by=c("ip.src","ip.dst","mbtcp.modbus.func_code"),suffixes=c(".n", ".a"))
mergedSrcFuncFreq[avgFrequencySec.n - avgFrequencySec.a,]

mergedSrcFuncRefFreq <- merge(srcFuncRefFreq,attackSrcFuncRefFreq, by=c("ip.src","ip.dst","mbtcp.modbus.func_code","mbtcp.modbus.reference_num"),suffixes=c(".n", ".a"))
mergedSrcFuncRefFreq[avgFrequncySec.n - avgFrequncySec.a,]
