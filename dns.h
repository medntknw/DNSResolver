#pragma once
#include <iostream>
#include<string>
#include<algorithm>
#include<utility>
#include <cstdint>
#include<bitset>
#include <cstring>

#include "util.h"

using namespace std;

constexpr uint16_t QR_MASK = 0x8000;  // Query/Response flag mask
constexpr uint16_t OPCODE_MASK = 0x7800;  // Opcode mask
constexpr uint16_t AA_MASK = 0x0400;  // Authoritative Answer flag mask
constexpr uint16_t TC_MASK = 0x0200;  // Truncated flag mask
constexpr uint16_t RD_MASK = 0x0100;  // Recursion Desired flag mask
constexpr uint16_t RA_MASK = 0x0080;  // Recursion Available flag mask
constexpr uint16_t RCODE_MASK = 0x000F;  // Response Code mask

// Define constants for flag positions after shifting
constexpr uint16_t OPCODE_SHIFT = 11;  // Opcode shift value
constexpr uint16_t RCODE_SHIFT = 0;   // Response Code shift value

enum Opcode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
};

enum ResponseCode {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
};

class Flags {
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    public:
        bool qr;
        uint16_t opcode;
        bool aa;
        bool tc;
        bool rd;
        bool ra;
        uint16_t rcode;

        Flags(uint16_t flags){
            qr = flags & QR_MASK;

            opcode = (flags & OPCODE_MASK) >> OPCODE_SHIFT;

            aa = flags & AA_MASK;

            tc = flags & TC_MASK;

            rd = flags & RD_MASK;

            ra = flags & RA_MASK;

            rcode = flags & RCODE_MASK;

        }
        string repr() const{
            return "Flags{QR=" + to_string(qr) +
                ", OPCODE=" + to_string(opcode) +
                ", AA=" + to_string(aa) +
                ", TC=" + to_string(tc) +
                ", RD=" + to_string(rd) +
                ", RA=" + to_string(ra) +
                ", RCODE=" + to_string(rcode) +
                "}";

        }
};

class Header{
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    public:
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;

        Header (){}

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
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
    public:
        string qname;
        uint16_t qtype;
        uint16_t qclass;

        Question(){}

        Question(string qname, uint16_t qtype, uint16_t qclass){
            this->qname = qname;
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
            vector<uint8_t> ascii = encodeDomain(this->qname);
            res += toBinary(ascii);
            res += qtype.to_string();
            res += qclass.to_string();
            return res;
        }
};

class ResourceRecord{
public:
    /*
    This RFS covers the all the new types https://datatracker.ietf.org/doc/html/rfc3596#section-2.1
    */
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

class DNSMessage{
    public:
        Header header;
        Question question;
        vector<ResourceRecord> answer;
        vector<ResourceRecord> authority;
        vector<ResourceRecord> additional;

        DNSMessage(Header h, Question q){
            this->header = h;
            this->question = q;
        }

        DNSMessage(Header h, vector<ResourceRecord> answer, vector<ResourceRecord> authority, vector<ResourceRecord> additional){
            this->header = h;
            this->answer = answer;
            this->authority = authority;
            this->additional = additional;
        }
};
