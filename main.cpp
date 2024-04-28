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

pair<string, bool> parseDNSMessage(const char* buffer, int length) {
    Header rheader = parseDNSHeader(buffer);

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

    if(answer.size() > 0){
        return {answer[0].rdata, true};
    }
    else{
        // querying root NS will return TLD domain in response
        if(authority.size() > 0){

            if(additional.size() <= 0){
                // additonal section doesn't provide IP for the TLD domain
                // query root NS to get the IP
                return {authority[0].rdata, false};
            }
            else{
                for(auto r: additional){
                    if(r.rdata.length() > 0) return {r.rdata, false};
                }
            }

        }
        else{
            throw runtime_error("No useful response from server");
        }
    }
    throw runtime_error("No useful response from server");
}

string generateDNSMessage(string domain){
    // hardcoding ID to check the response for testing
    Header h(22, (1<<8), 1, 0, 0, 0);
    Question q(domain, 1, 1);
    string header_hex = toHex(h.to_binary());
    string question_hex = toHex(q.to_binary());
    return hexToBytes(header_hex + question_hex);
}

char* queryServer(string domain, const char* server_ip){
    string dns_message = generateDNSMessage(domain);
    // Send query to DNS server
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        cerr << "Error creating socket" << endl;
        throw runtime_error("Error creating socket");
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
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

int main(int argc, char *argv[]){
    string domain = "dns.google.com";
    pair<string, bool> result = {"198.41.0.4", false};
    while(!result.second){
        cout<<"Querying: "<<result.first<<" for: "<<domain<<endl;
        char* buffer = queryServer(domain, result.first.c_str());
        result = parseDNSMessage(buffer, sizeof(buffer));
    }
    cout<<"IP for domain: "<<domain<<" = "<<result.first<<endl;
}
