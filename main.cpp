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

#include "util.h"

using namespace std;
constexpr int MAX_BUFFER_SIZE = 5000;

class Header{
    public:
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
        Header(uint16_t _id, uint16_t _flags, uint16_t _qdcount, uint16_t _ancount, uint16_t _nscount, uint16_t _arcount){
            this->id = _id;
            this->flags = _flags;
            this->qdcount = _qdcount;
            this->ancount = _ancount;
            this->nscount = _nscount;
            this->arcount = _arcount;
        }
    
        string to_binary(){
            bitset<16> id(this->id), flags(this->flags), qdcount(this->qdcount), ancount(this->ancount), nscount(this->nscount), arcount(this->arcount);
            string res = "";
            res += id.to_string();
            res += flags.to_string();
            res += qdcount.to_string();
            res += ancount.to_string();
            res += nscount.to_string();
            res += arcount.to_string();
            return res;
        }
        string repr() const {
            return "Header{id=" + to_string(id) +
                ", flags=" + to_string(flags) +
                ", qdcount=" + to_string(qdcount) +
                ", ancount=" + to_string(ancount) +
                ", nscount=" + to_string(nscount) +
                ", arcount=" + to_string(arcount) +
                "}";
         }
};

class Question{
    public:
        string qname;
        uint16_t qtype;
        uint16_t qclass;
    
        Question(string qname, uint16_t qtype, uint16_t qclass){
            this->qname = encode(qname);
            this->qtype = qtype;
            this->qclass = qclass;
        }

        string repr() const {
            return "Question{qname=" + qname +
                ", qtype=" + to_string(qtype) +
                ", qclass=" + to_string(qclass) +
                "}";
         }

        string to_binary(){
            bitset<16> qtype(this->qtype), qclass(this->qclass);
            string res = "";
            res += asciiToBinary(toASCII(this->qname));
            res += qtype.to_string();
            res += qclass.to_string();
            return res;
        }
};

class ResourceRecord{
public:
    string name;
    uint16_t type;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    string rdata;

    ResourceRecord(string name, uint16_t type, uint16_t rclass, uint32_t ttl, uint16_t rdlength, string rdata){
        this->name = name;
        this->type = type;
        this->rclass = rclass;
        this->ttl = ttl;
        this->rdlength = rdlength;
        this->rdata = rdata;
    }
    string repr() const {
        return "RR{name=" + name +
                ", type=" + to_string(type) +
                ", rclass=" + to_string(rclass) +
                ", ttl=" + to_string(ttl) +
                ", rdlength=" + to_string(rdlength) +
                ", rdata=" + rdata +
                "}";
    }

};

Header parseDNSHeader(const char* buffer) {
    uint16_t id = ntohs(*reinterpret_cast<const uint16_t*>(buffer));
    uint16_t flags = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 2));
    uint16_t qdcount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 4));
    uint16_t ancount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 6));
    uint16_t nscount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 8));
    uint16_t arcount = ntohs(*reinterpret_cast<const uint16_t*>(buffer + 10));
    Header header(id, flags, qdcount, ancount, nscount, arcount);
    cout<<header.repr()<<endl;
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
    offset += rdlength;
    ResourceRecord rr(name, type, rclass, ttl, rdlength, rdata);
    cout<<rr.repr()<<endl;
    return rr;
}

void parseDNSMessage(const char* buffer, int length) {
    Header rheader = parseDNSHeader(buffer);

    int offset = sizeof(Header);

    for (int i = 0; i < rheader.qdcount; ++i) {
        parseDomainNames(buffer, offset);
        offset += 4;
    }

    vector<ResourceRecord> answer, authority, additional;
    for (int i = 0; i < rheader.ancount; ++i) {
        answer.push_back(parseResourceRecord(buffer, offset));
    }

    for (int i = 0; i < rheader.nscount; ++i) {
        authority.push_back(parseResourceRecord(buffer, offset));
    }

    for (int i = 0; i < rheader.arcount; ++i) {
        additional.push_back(parseResourceRecord(buffer, offset));
    }
}

string generateDNSMessage(string domain){
    // hardcoding ID to check the response for testing
    Header h(22, (1<<8), 1, 0, 0, 0);
    Question q(domain, 1, 1);
    cout<<h.repr()<<endl;
    cout<<q.repr()<<endl;
    string header_hex = toHex(h.to_binary());
    string question_hex = toHex(q.to_binary());
    return hexToBytes(header_hex + question_hex);
}

int main(int argc, char *argv[]){
    
    string dns_message = generateDNSMessage("dns.google.com");

    // Send query to DNS server
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        cerr << "Error creating socket" << endl;
        return 1;
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(53);
    server_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

    ssize_t bytes_sent = sendto(sockfd, dns_message.data(), dns_message.size(), 0,
                                 (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (bytes_sent == -1) {
        cerr << "Error sending DNS message" << endl;
        close(sockfd);
        return 1;
    }

    // Receive response from DNS server
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[MAX_BUFFER_SIZE];
    ssize_t bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                                  (struct sockaddr*)&client_addr, &client_len);
    if (bytes_received == -1) {
        cerr << "Error receiving DNS response" << endl;
        close(sockfd);
        return 1;
    }
    cout << "Received " << bytes_received << " bytes of data:" << endl;

    // Parse Response
    parseDNSMessage(buffer, sizeof(buffer));
    close(sockfd);

}
