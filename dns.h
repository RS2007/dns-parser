#pragma once

#include <assert.h>
#include <cstring>
#include <iostream>
#include <numeric>
#include <stdint.h>
#include <string>
#include <vector>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#else
#include <endian.h>
#endif

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
  while (true) {
    if ((q_start[i] & 0b11000000) == 0b11000000) {
      q_start = orig_buffer + (htobe16((*(uint16_t *)q_start)) & 0x3FFF);
    }
    len = q_start[i];
    if (q_start[++i] == (char)0) {
      break;
    }
    std::string name;
    for (int j = 0; j < len; j++) {
      name.push_back((char)q_start[i + j]);
    }
#ifdef DEBUG
    std::cout << "Name is: " << name << "\n";
#endif
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
    "INVALID", "A",  "NS",  "MD",   "MF",  "CNAME", "SOA",
    "MB",      "MG", "MR",  "NULL", "WKS", "PTR",   "HINFO",
    "MINFO",   "MX", "TXT", "AAAA", "SRV", "OPT",   "NSEC",
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
  AAAA,
  SRV,
  OPT,
  NSEC,
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

dns_name_string *parse_A(char *bytes) {
  auto ipAddress = htobe32(*(uint32_t *)(bytes));
  unsigned char octet1, octet2, octet3, octet4;

  octet1 = (ipAddress >> 24) & 0xFF;
  octet2 = (ipAddress >> 16) & 0xFF;
  octet3 = (ipAddress >> 8) & 0xFF;
  octet4 = ipAddress & 0xFF;
  char *ip_addr = (char *)malloc(16);
  snprintf(ip_addr, 16, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
  dns_name_string *ret = (dns_name_string *)malloc(sizeof(dns_name_string));
  ret->name = ip_addr;
  ret->len = 4;
  return ret;
}

dns_name_string *parse_AAAA(char *bytes) {
  typedef struct {
    uint64_t top;
    uint64_t bottom;
  } uint128_t;
  uint128_t buffer = *(uint128_t *)bytes;
  char *ipv6_addr = (char *)malloc(41);
  snprintf(ipv6_addr, 41, "%016llx:%016llx", (unsigned long long)buffer.top,
           (unsigned long long)buffer.bottom);
  dns_name_string *parsed = (dns_name_string *)malloc(sizeof(dns_name_string));
  parsed->name = ipv6_addr;
  parsed->len = 16;
  return parsed;
}

size_t parse_answer(char *bytes, DNS_Resource_t *answer, char *orig_buffer) {
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
    dns_name_string *parsed = parse_A(bytes + 2 + sizeof(fixed_size_packet));
    answer->r_data = parsed->name;
    return 2 + sizeof(fixed_size_packet) + parsed->len;
    break;
  }
  case AAAA: {
    std::cout << "Untested feature: Use at your own risk\n";
    dns_name_string *parsed = parse_AAAA(bytes + 2 + sizeof(fixed_size_packet));
    answer->r_data = parsed->name;
    return 2 + sizeof(fixed_size_packet) + parsed->len;
  }
  case CNAME: {
    dns_name_string *parsed =
        get_name(bytes + 2 + sizeof(fixed_size_packet), orig_buffer);
    answer->r_data = parsed->name;
    return 2 + sizeof(fixed_size_packet) + parsed->len;
  }
  case NS: {
    dns_name_string *parsed =
        get_name(bytes + 2 + sizeof(fixed_size_packet), orig_buffer);
    answer->r_data = parsed->name;
    return 2 + sizeof(fixed_size_packet) + parsed->len;
  }
  case TXT: {
    char *parsed = (char *)(bytes + 2 + sizeof(fixed_size_packet));
    answer->r_data = parsed;
    return 2 + sizeof(fixed_size_packet) + strlen(parsed);
  }
  default: {
    assert(0 && "Not implemented");
  }
  }
};
