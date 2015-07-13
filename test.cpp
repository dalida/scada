/*
 * processCSV.cpp
 *
 * MALIPHOL
 * 7/2015
 *
 * Merge MODBUS/TCP request/response transactions.
 *
 * Compile:
 *   g++ processCSV.cpp -o processCSV -std=c++11 -lpthread
 *
 */

#include <iostream>
#include <string>
#include <sstream>
#include <cstring>


using namespace std;


int hexToDec(const string& str) {

	return strtol(str.c_str(), NULL, 16);
}

int hexToDec1(string str) {

	char delim[] = ":";
	char *token;
	token = strtok(&str[0], delim);
	string decS;

	while (token != NULL) {
		cout<< token << "\n";
		decS += token;
		token = strtok( NULL, delim);
	}
	cout<< strtol(decS.c_str(), NULL, 16) <<endl;

}

int main() {

	stringstream sstr;
	sstr << "0075";
	sstr << hex;
	int f;
	sstr >> f;
	cout << f;

	cout <<"\n";

	//char str[] = "1214";
	char str[] = "0acc";
	//cout << strtol(str, NULL, 16);
	//cout <<"\n";

    cout << str << " " << hexToDec(str) << endl;
    cout << "0054"<< " " << hexToDec("0054") << endl;
    cout << "0075"<< " " << hexToDec("0075") << endl;
    cout << "0050"<< " " << hexToDec("0050") << endl;
    cout << "1214"<< " " << hexToDec("1214") << endl;
    cout << "120a"<< " " << hexToDec("120a") << endl;
    cout << "0acc"<< " " << hexToDec("0acc") << endl;

	
	cout << "-----------------------\n\n";
	char inp[] = "00:54";
	hexToDec1(inp);

	return 0;
}
