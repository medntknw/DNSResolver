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

string toBinary(vector<uint8_t>& input){
    string binary="";
    for(auto i: input){
        bitset<8>b(i);
        string bstr = b.to_string();
        binary += bstr;
    }
    return binary;
}
vector<uint8_t> encodeDomain(const string& domain) {
    vector<uint8_t> encoded;
    string label;
    size_t pos = 0;

    while (pos < domain.length()) {
        size_t dotPos = domain.find('.', pos);
        if (dotPos == string::npos) {
            label = domain.substr(pos);
            pos = domain.length();
        } else {
            label = domain.substr(pos, dotPos - pos);
            pos = dotPos + 1;
        }

        encoded.push_back(static_cast<uint8_t>(label.length()));
        for (char c : label) {
            encoded.push_back(static_cast<uint8_t>(c));
        }
    }
    encoded.push_back(0);
    return encoded;
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
    string rdata = "";
    // rclass = 1 = Internet
    // type = 1 = A = Ipv4 host address
    if (type == 1 && rclass == 1 && rdlength == 4) {
        char ipv4Address[4];
        memcpy(ipv4Address, buffer + offset, 4);
        struct in_addr addr;
        memcpy(&addr, ipv4Address, 4);
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
        rdata = ipStr;
        offset += rdlength;
    }
    // type = 2 = NS = authoritative NS
    else if(type == 2 && rclass == 1){
        string nsdomain = parseDomainNames(buffer, offset);
        rdata = nsdomain;
    }
    // type = 28 = AAAA = Ipv6 host address
    else if(type == 28 && rclass == 1 && rdlength == 16){
        char ipv6Address[16];
        memcpy(ipv6Address, buffer + offset, 16);

        // Convert network byte order to host byte order
        struct in6_addr addr;
        memcpy(&addr, ipv6Address, 16);

        char ipStr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr, ipStr, INET6_ADDRSTRLEN);
        rdata = ipStr;
        offset += rdlength;

    }
    // type = 5 = CNAME = canonical name for an alias
    else if(type == 5 && rclass == 1){
        string cname = parseDomainNames(buffer, offset);
        rdata = cname;
    }
    else {
        // cerr << "Unsupported RDATA type or class" << endl;
        offset += rdlength;
    }
    return rdata;
}