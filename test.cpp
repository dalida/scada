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


using namespace std;


int hexToDec(const string& str) {
//int hexToDec(char str[]) {
//long int hexToDec(char str[]) {

//	int dec;
	//long int dec;
	//cout << str;
	//cout << "\n";

//	dec = strtol(str.c_str(), NULL, 16);
	//cout << dec;
	//cout << "\n";

	return strtol(str.c_str(), NULL, 16);
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

    cout << hexToDec(str);
	cout << "\n";

	return 0;
}
