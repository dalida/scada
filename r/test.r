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


print(nrow(sewModbusDT))

print(nrow(mergedSewDT))

cat(pi^2,"\n")
