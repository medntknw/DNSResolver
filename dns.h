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
