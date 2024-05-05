#include <iostream>
#include<string>
#include<algorithm>
#include<utility>
#include <cstdint>
#include<bitset>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>

#include "util.h"
#include "dns.h"

using namespace std;
constexpr int MAX_BUFFER_SIZE = 5000;

const string ROOT_NS[13] = {
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33"
};


Header parseDNSHeader(const char* buffer) {
    uint16_t id = ntohs(*reinterpret_cast<const uint16_t*>(buffer));
    uint16_t flags = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
    uint16_t qdcount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 4));
    uint16_t ancount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 6));
    uint16_t nscount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 8));
    uint16_t arcount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 10));
    Header header(id, flags, qdcount, ancount, nscount, arcount);
    return header;
}

ResourceRecord parseResourceRecord(const char* buffer, int& offset) {
    string name = parseDomainNames(buffer, offset);
    uint16_t type = ntohs(*reinterpret_cast<const uint16_t*>(buffer + offset));
    offset += 2;
    uint16_t rclass = ntohs(*reinterpret_cast<const uint16_t*>(buffer + offset));
    offset += 2;
    uint32_t ttl = ntohl(*reinterpret_cast<const uint32_t*>(buffer + offset));
    offset += 4;
    uint16_t rdlength = ntohs(*reinterpret_cast<const uint16_t*>(buffer + offset));
    offset += 2;
    string rdata = parseRDATA(buffer, offset, type, rclass, rdlength);
    ResourceRecord rr(name, type, rclass, ttl, rdlength, rdata);
    return rr;
}

DNSMessage parseDNSMessage(const char* buffer, int length) {
    Header rheader = parseDNSHeader(buffer);

    Flags flags(rheader.flags);

    int offset = sizeof(Header);

    for (int i = 0; i < rheader.qdcount; ++i) {
        parseDomainNames(buffer, offset);
        offset += 4;
    }

    vector<ResourceRecord> answer, authority, additional;
    for (int i = 0; i < rheader.ancount; ++i) {
        // cout<<"Parsing Answer Section: "<<endl;
        answer.push_back(parseResourceRecord(buffer, offset));
    }

    for (int i = 0; i < rheader.nscount; ++i) {
        // cout<<"Parsing Authority Section: "<<endl;
        authority.push_back(parseResourceRecord(buffer, offset));
    }

    for (int i = 0; i < rheader.arcount; ++i) {
        // cout<<"Parsing Additional Section: "<<endl;
        additional.push_back(parseResourceRecord(buffer, offset));
    }
    return DNSMessage(rheader, answer, authority, additional);
}

string generateDNSMessage(string domain, int qtype){
    // hardcoding ID to check the response for testing
    Header h(22, 0, 1, 0, 0, 0);
    Question q(domain, qtype, 1);
    string hex_dns = toHex(h.to_binary() + q.to_binary());
    return hexToBytes(hex_dns);
}

char* queryServer(string domain, const char* server_ip, int qtype){

    cout<<"Querying "<<server_ip<<" for "<<domain<<" qtype: "<<qtype<<endl;
    string dns_message = generateDNSMessage(domain, qtype);

    // Create socket (File descriptor) with Protocol Family Interent and SOCK_DGRAM type
    int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        cerr << "Error creating socket" << endl;
        throw runtime_error("Error creating socket");
    }
    // Create socket address
    // We are using sockaddr_in instead of sockaddr as we don't want to deal with sa_data, both can be type casted to each other.
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET; // Address Family Interent
    server_addr.sin_port = htons(53); // Host to Network byte order short
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    ssize_t bytes_sent = sendto(sockfd, dns_message.data(), dns_message.size(), 0,
                                 (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (bytes_sent == -1) {
        cerr << "Error sending DNS message" << endl;
        close(sockfd);
        throw runtime_error("Error sending DNS message");
    }

    // Receive response from DNS server
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char* buffer = new char[MAX_BUFFER_SIZE];
    ssize_t bytes_received = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0,
                                  (struct sockaddr*)&client_addr, &client_len);
    if (bytes_received == -1) {
        cerr << "Error receiving DNS response" << endl;
        close(sockfd);
        throw runtime_error("Error receiving DNS response");
    }
    cout << "Received " << bytes_received << " bytes of data" << endl;
    return buffer;
}

pair<int, string> processDNSMessage(DNSMessage msg){
    /*
    {1, x} -> Found the answer 
    {2, x} -> Found the Authoritative NS IP
    {3, x} -> Found the Authoritative NS domain

    */
    string ip = "";
    string server = "";
    string ns = "";
    if(msg.answer.size() > 0){
        ip = msg.answer[0].rdata;
        if(ip.length() == 0){
            cout<<"Not able to process rdata in Answer: "<<msg.answer[0].repr()<<endl;
        }
    }
    else{
        if(msg.authority.size() > 0){
            if(msg.additional.size() > 0){
                server = msg.additional[0].rdata;
                if(server.length() == 0){
                    cout<<"Not able to process rdata in Additional: "<<msg.additional[0].repr()<<endl;
                }
            }
            else{
                ns = msg.authority[0].rdata;
                if(ns.length() == 0){
                    cout<<"Not able to process rdata in Authority: "<<msg.authority[0].repr()<<endl;
                }
            }
        }
    }
    if(ip.length() > 0) return {1, ip};
    if(server.length() > 0) return {2, server};
    if(ns.length() > 0) return {3, ns};
    cout<<"Receieved error from the server: "<< msg.header.repr()<<endl<<Flags(msg.header.flags).repr()<<endl;
    throw logic_error("Not able to process DNS Message!");
}

string resolveIp(string domain){
    string server = ROOT_NS[0];
    char* buffer = queryServer(domain, server.c_str(), 1);
    DNSMessage msg = parseDNSMessage(buffer, sizeof(buffer));
    pair<int, string> res = processDNSMessage(msg);
    while (true) {
        if (res.first == 1) {
            cout << "Resolved IP address: " << res.second << endl;
            return res.second;
        } else if (res.first == 2) {
            cout << "Found Authoritative NS IP in RR: " << res.second << endl;
            buffer = queryServer(domain, res.second.c_str(), 1);
            msg = parseDNSMessage(buffer, sizeof(buffer));
            res = processDNSMessage(msg);
        } else if (res.first == 3) {
            cout << "Querying to get the IP address for: " << res.second << endl;
            server = resolveIp(res.second);
            buffer = queryServer(domain, server.c_str(), 1);
            msg = parseDNSMessage(buffer, sizeof(buffer));
            res = processDNSMessage(msg);
        }
    }
}

int main(int argc, char *argv[]){
    string domain = "app.eightfold.ai";
    cout<<resolveIp(domain)<<endl;
}
