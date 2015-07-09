/*
 * processCSV.cpp
 *
 * MALIPHOL
 * 7/2015
 *
 * Merge MODBUS/TCP request/response transactions from pcap
 * file that has captured NORMAL MODBUS/TCP network traffic,
 * ie, there are two packets per mbtcp transaction ID, one
 * request, followed by a response.
 *
 * Compile:
 *   g++ processCSV.cpp -o processCSV -std=c++11 -lpthread
 *
 */

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>

#include "lib/csv.h"

using namespace std;
using namespace io;


// ********************* VARIABLES ********************* 

// debug
const bool check = 1;

const string FILENAME = "mb2k.dat";

// number of variables in packet
const int packetLen = 18;

// Packet
struct packetStr {
	int    frameNumber;
	double frameTimeRel;
    double frameTimeDeltaDisplay;
	int    frameLen;
	char   ipProto;
    char   ipVersion;
    string ipSrc;
	string ipDst;
	string mbtcpModbusUnitId;
	string tcpSrcPort;
	string tcpDstPort;
	char   mbtcpProtId;
	int    mbtcpTransId;
	int    mbtcpLen;
	string mbtcpModbusFuncCode;
	string mbtcpModbusRefNum;
	int    mbtcpModbusWordCnt;
	string mbtcpModbusData;
} packet, prevPacket;

// merged mbtcp transaction
struct mbtcpTransStr {
	int    frameNumber;
	double frameTimeRel;
    double frameTimeDeltaDisplay;
	int    frameLen;
	char   ipProto; //
    char   ipVersion; //
    string ipSrc;
	string ipDst;
	string mbtcpModbusUnitId;
	string tcpSrcPort;
	string tcpDstPort;
	char   mbtcpProtId;
	int    mbtcpTransId;
	int    mbtcpLen;
	string mbtcpModbusFuncCode;
	string mbtcpModbusRefNum;
	int    mbtcpModbusWordCnt;
    int    respFrNumber;
    double respTimeRel;
    double respTimeDelta;
    int    respLen;
    string respSrc;
    string respDest;
    string respUnitId;
    string respSrport;
    string respDstPort;
    int    respProtId;
    int    respTransId;
    string respMbtcpLen;
    string respFuncCode;
	string mbtcpModbusData;
	int    d;
} mbtcpTrans;

// all merged mbtcp transactions
vector<mbtcpTransStr> mergedTrans;


// ********************* FUNCTIONS ********************* 

int hexToDec(const string& str) {

	return strtol(str.c_str(), NULL, 16);
}

// ************************ MAIN ************************

int main() {

	cout<<"Processing file :" + FILENAME + "\n";

	CSVReader<packetLen> in( FILENAME.c_str() );
	while( in.read_row(
			   packet.frameNumber, packet.frameTimeRel, packet.frameTimeDeltaDisplay,
			   packet.frameLen, packet.ipProto, packet.ipVersion, packet.ipSrc, packet.ipDst,
			   packet.mbtcpModbusUnitId, packet.tcpSrcPort, packet.tcpDstPort, packet.mbtcpProtId,
			   packet.mbtcpTransId, packet.mbtcpLen, packet.mbtcpModbusFuncCode,
			   packet.mbtcpModbusRefNum, packet.mbtcpModbusWordCnt, packet.mbtcpModbusData 
			   ) ) {

		// merge request and response packets
		if( packet.mbtcpTransId == prevPacket.mbtcpTransId) {

			//printf("mbtcpTransId: %d \n", packet.mbtcpTransId);
			// request packet has destination port 502
			if( prevPacket.tcpDstPort == "502" ) {
				//printf("   Frame request: %d\n", prevPacket.frameNumber);

				mbtcpTrans.frameNumber  = prevPacket.frameNumber;
				mbtcpTrans.frameTimeRel = prevPacket.frameTimeRel;
				mbtcpTrans.frameTimeDeltaDisplay = prevPacket.frameTimeDeltaDisplay;
				mbtcpTrans.frameLen     = prevPacket.frameLen;
				mbtcpTrans.ipProto      = prevPacket.ipProto;
				mbtcpTrans.ipVersion    = prevPacket.ipVersion;
				mbtcpTrans.ipSrc        = prevPacket.ipSrc;
				mbtcpTrans.ipDst        = prevPacket.ipDst;
				mbtcpTrans.mbtcpModbusUnitId = prevPacket.mbtcpModbusUnitId;
				mbtcpTrans.tcpSrcPort   = prevPacket.tcpSrcPort;
				mbtcpTrans.tcpDstPort   = prevPacket.tcpDstPort;
				mbtcpTrans.mbtcpProtId  = prevPacket.mbtcpProtId;
				mbtcpTrans.mbtcpTransId = prevPacket.mbtcpTransId;
				mbtcpTrans.mbtcpLen     = prevPacket.mbtcpLen;
				mbtcpTrans.mbtcpModbusFuncCode = prevPacket.mbtcpModbusFuncCode;
				mbtcpTrans.mbtcpModbusRefNum   = prevPacket.mbtcpModbusRefNum;
				mbtcpTrans.mbtcpModbusWordCnt  = prevPacket.mbtcpModbusWordCnt;
			}

			// response packet has source port 502
			if( packet.tcpSrcPort == "502" ) {
				//printf("   Frame response: %d\n", packet.frameNumber);

				mbtcpTrans.respFrNumber = packet.frameNumber;
				mbtcpTrans.respTimeRel  = packet.frameTimeRel;
				mbtcpTrans.respTimeDelta = packet.frameTimeDeltaDisplay;
				mbtcpTrans.respLen       = packet.frameLen;
				mbtcpTrans.respSrc       = packet.ipSrc;
				mbtcpTrans.respDest      = packet.ipDst;
				mbtcpTrans.respUnitId   = packet.mbtcpModbusUnitId;
				mbtcpTrans.respSrport    = packet.tcpSrcPort;
				mbtcpTrans.respDstPort   = packet.tcpDstPort;
				mbtcpTrans.respProtId    = packet.mbtcpProtId;
				mbtcpTrans.respTransId   = packet.mbtcpTransId;
				mbtcpTrans.respMbtcpLen  = packet.mbtcpLen;
				mbtcpTrans.respFuncCode  = packet.mbtcpModbusFuncCode;
				mbtcpTrans.mbtcpModbusData = packet.mbtcpModbusData; 
				mbtcpTrans.d = hexToDec(packet.mbtcpModbusData); 
			}

			// add to all merged transactions
			mergedTrans.push_back(mbtcpTrans);

			// re-initialize transaction
			mbtcpTrans = (const struct mbtcpTransStr){ 0 };
		}

		prevPacket = packet;

	} // end while read_row

	printf("number of merged trans: %d\n", mergedTrans.size());;


	// check
	if (check) {
		cout<<"checking....\n";

		for( auto &i : mergedTrans ) {
			cout<< i.frameNumber << endl;
		}

	}

} // end main
