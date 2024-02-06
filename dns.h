#pragma once

#include <assert.h>
#include <cstring>
#include <endian.h>
#include <iostream>
#include <numeric>
#include <stdint.h>
#include <string>
#include <vector>

typedef struct __attribute__((packed)) {
  uint16_t id;
  uint16_t flags;
  uint16_t question_count;
  uint16_t answer_count;
  uint16_t authorities_count;
  uint16_t additional_count;
} DNS_Header_t;

DNS_Header_t *parse_header(char *bytes) { return (DNS_Header_t *)bytes; }

/* |                                               | */
/* /                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ */

typedef struct {
  char *q_name;
  uint16_t q_type;
  uint16_t q_class;
} DNS_Question_t;

typedef struct {
  char *name;
  size_t len;
} dns_name_string;

dns_name_string *get_name(char *bytes, char *orig_buffer) {
  size_t i = 0;
  size_t len;
  std::vector<std::string> names;
  char *q_start = (char *)bytes;
  if ((q_start[i] & 0b11000000) == 0b11000000) {
    q_start = orig_buffer + (htobe16((*(uint16_t *)q_start)) & 0x3FFF);
  }
  len = q_start[i];
  while (q_start[++i] != (char)0) {
    std::string name;
    for (int j = 0; j < len; j++) {
      name.push_back((char)q_start[i + j]);
    }
    std::cout << "Name is: " << name << "\n";
    i += len;
    len = q_start[i];
    names.push_back(name);
  }
  char delimiter = '.';
  std::string domain_name_str =
      std::accumulate(std::next(names.begin()), names.end(), names[0],
                      [&delimiter](std::string &acc, const std::string &s) {
                        return acc + delimiter + s;
                      });
  char *domain_name = (char *)malloc(domain_name_str.size());
  strncpy(domain_name, domain_name_str.c_str(), domain_name_str.size());
  domain_name[domain_name_str.size()] = '\0';
  auto dns_name = (dns_name_string *)malloc(sizeof(dns_name_string));
  dns_name->name = domain_name;
  dns_name->len = i;
  return dns_name;
}

size_t parse_question(char *bytes, DNS_Question_t *question,
                      char *orig_buffer) {
  auto dns_name = get_name(bytes, orig_buffer);
  question->q_name = dns_name->name;
  typedef struct __attribute__((packed)) {
    uint16_t q_type;
    uint16_t q_class;
  } q_type_class_t;
  auto q_type_class = (q_type_class_t *)(bytes + dns_name->len);
  question->q_type = htobe16(q_type_class->q_type);
  question->q_class = htobe16(q_type_class->q_class);
  return dns_name->len + 4;
}
static std::string dns_type_strings[] = {
    "INVALID", "A",    "NS",  "MD",  "MF",    "CNAME", "SOA", "MB", "MG",
    "MR",      "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX",  "TXT"};

static std::string dns_class_strings[] = {"INVALID", "IN", "CS", "CH", "HS"};

static std::string dns_resource_type_strings[] = {
    "INVALID", "A",    "NS",  "MD",  "MF",    "CNAME", "SOA", "MB",  "MG",
    "MR",      "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX",  "TXT",
};

typedef enum : uint16_t {
  INVALID,
  A,
  NS,
  MD,
  MF,
  CNAME,
  SOA,
  MB,
  MG,
  MR,
  NULLE,
  WKS,
  PTR,
  HINFO,
  MINFO,
  MX,
  TXT,
} RRTYPE;

static std::string dns_resource_class_strings[] = {"INVALID", "IN", "CS", "CH",
                                                   "HS"};

typedef struct {
  char *r_name;
  uint16_t r_type;
  uint16_t r_class;
  uint32_t r_ttl;
  uint16_t r_rdlength;
  char *r_data;
} DNS_Resource_t;

inline void parse_answer(char *bytes, DNS_Resource_t *answer,
                         char *orig_buffer) {
  auto dns_name = get_name(bytes, orig_buffer);
  answer->r_name = dns_name->name;
  typedef struct __attribute__((packed)) {
    RRTYPE r_type;
    uint16_t r_class;
    uint32_t r_ttl;
    uint16_t r_rdlength;
  } fixed_size_packet;
  auto f_size_packet = (fixed_size_packet *)(bytes + 2);
  answer->r_class = htobe16(f_size_packet->r_class);
  answer->r_type = htobe16(f_size_packet->r_type);
  answer->r_ttl = htobe32(f_size_packet->r_ttl);
  answer->r_rdlength = htobe16(f_size_packet->r_rdlength);
  switch (answer->r_type) {
  case A: {
    uint32_t ipAddress = htobe32(*(uint32_t*)(bytes+2+sizeof(fixed_size_packet)));
    unsigned char octet1, octet2, octet3, octet4;

    octet1 = (ipAddress >> 24) & 0xFF;
    octet2 = (ipAddress >> 16) & 0xFF;
    octet3 = (ipAddress >> 8) & 0xFF;
    octet4 = ipAddress & 0xFF;
    char* ip_addr = (char*)malloc(16);
    snprintf(ip_addr,16,"%d.%d.%d.%d",octet1,octet2,octet3,octet4);
    answer->r_data = ip_addr;
    break;
  }
  default: {
    assert(0 && "Not implemented");
  }
  }
  return;
};
