#pragma once
#include <iostream>
#include<string>
#include<algorithm>
#include<utility>
#include<queue>
#include<unordered_map>
#include<bitset>

using namespace std;

string toHex(string binary){
    binary = string(binary.length() % 4 ? 4 - binary.length() % 4 : 0, '0') + binary; 
    unordered_map<string, char> hex_dict = { 
        {"0000", '0'}, {"0001", '1'}, {"0010", '2'}, {"0011", '3'}, 
        {"0100", '4'}, {"0101", '5'}, {"0110", '6'}, {"0111", '7'}, 
        {"1000", '8'}, {"1001", '9'}, {"1010", 'a'}, {"1011", 'b'}, 
        {"1100", 'c'}, {"1101", 'd'}, {"1110", 'e'}, {"1111", 'f'} 
    }; 
    string hexadecimal; 
    for (size_t i = 0; i < binary.length(); i += 4) { 
        string group = binary.substr(i, 4); 
        hexadecimal += hex_dict[group];
    } 
    return hexadecimal; 
}

string asciiToBinary(vector<uint8_t> ascii){
    string binary="";
    for(auto i: ascii){
        bitset<8>b(i);
        string bstr = b.to_string();
        binary += bstr;
    }
    return binary;
}

vector<uint8_t> toASCII(string s){
    vector<uint8_t>ascii;
    for(int i=0;i<s.length();++i){
        char c = s[i];
        uint8_t d = c;
        if(d>=97){
            ascii.push_back(d);
        }
        else{
            int j=i;
            uint8_t num = 0;
            while(j<s.length() && (uint8_t)s[j] < 97){
                num = num*10 + (uint8_t)(s[j]-'0');
                j++;
            }
            ascii.push_back(num);
            i = j-1;
        }
    }
    return ascii;
}

string encode(string s){
    string res = "";
    queue<char>st;
    for(char c: s){
        if(c == '.'){
            res+=to_string(st.size());
            while(!st.empty()){
                res+=st.front();
                st.pop();
            }
        }
        else{
            st.push(c);
        }
    }
    if(!st.empty()){
        res+=to_string(st.size());
        while(!st.empty()){
            res+=st.front();
            st.pop();
        }
    }
    res+='0';
    return res;
}

string hexToBytes(string hex){
    string bytes;
    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t byte = stoul(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

string parseDomainNames(const char* buffer, int& offset) {
    string domainName;
    bool compressed = false;
    int initialOffset = offset;

    while (true) {
        // 0xC0 -> 11000000
        // Check RFC for more details -> https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
        if ((buffer[offset] & 0xC0) == 0xC0) {
            if (!compressed) {
                compressed = true;
                initialOffset = offset + 2;
            }
            // 0x3F -> 00111111
            offset = ((buffer[offset] & 0x3F) << 8) | static_cast<uint8_t>(buffer[offset + 1]);
        } else {
            int labelLength = static_cast<uint8_t>(buffer[offset]);
            offset++;

            if (labelLength == 0) {
                if (!compressed) {
                    initialOffset = offset;
                }
                break;
            }
            domainName.append(buffer + offset, labelLength);
            offset += labelLength;

            if (buffer[offset] != 0) {
                domainName.push_back('.');
            }
        }
    }

    offset = initialOffset;
    return domainName;
}

string parseRDATA(const char* buffer, int& offset, uint16_t type, uint16_t rclass, uint16_t rdlength) {
    // 0xFF -> 11111111
    string rdata = "";
    if (type == 1 && rclass == 1 && rdlength == 4) {
        uint32_t ipv4Address = ntohl(*reinterpret_cast<const uint32_t*>(buffer + offset));
        string ipAddress = to_string((ipv4Address >> 24) & 0xFF) + "." +
                                to_string((ipv4Address >> 16) & 0xFF) + "." +
                                to_string((ipv4Address >> 8) & 0xFF) + "." +
                                to_string(ipv4Address & 0xFF);
        rdata = ipAddress;
    } else {
        cout << "Unsupported RDATA type or class" << endl;
    }
    return rdata;
}