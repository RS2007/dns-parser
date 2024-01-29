#pragma once

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

DNS_Header_t *parse_header(const char *bytes) { return (DNS_Header_t *)bytes; }

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

size_t parse_question(const char *bytes, DNS_Question_t *question) {
  size_t i = 0;
  size_t len;
  std::vector<std::string> names;
  const char *q_start = bytes + sizeof(DNS_Header_t);
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
  question->q_name = domain_name;
  typedef struct __attribute__((packed)) {
    uint16_t q_type;
    uint16_t q_class;
  } q_type_class_t;
  auto q_type_class = (q_type_class_t *)(q_start + i);
  question->q_type = htobe16(q_type_class->q_type);
  question->q_class = htobe16(q_type_class->q_class);
  return i + 4;
}

static std::string dns_type_strings[] = {
    "NULL", "A",    "NS",  "MD",  "MF",    "CNAME", "SOA", "MB", "MG",
    "MR",   "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX",  "TXT"};

static std::string dns_class_strings[] = {"NULL", "IN", "CS", "CH", "HS"};
