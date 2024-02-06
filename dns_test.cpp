#include "dns.h"
#include <cstring>
#include <endian.h>
#include <iostream>
#include <vector>

std::vector<char> HexToBytes(const std::string &hex) {
  std::vector<char> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char byte = (char)strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

void test_dns_header_parse() {
  std::vector<char> bytes1 = HexToBytes(
      "a0208180000100010000000105666f6e74730a676f6f676c656170697303636f6d000001"
      "0001c00c00010001000000ae00048efab64a0000290200000000000000");
  /* std::vector<char> bytes1 =
   * HexToBytes("ec2e98e9046b34e894fa3f5e08004500006b030400003e11f7c4c0a80001c0a80068003581c300577fa37baf818000010001000000010f7a2d7034322d696e7374616772616d046331307209696e7374616772616d03636f6d0000010001c00c000100010000000c00049df017ae0000290200000000000000");
   */
  std::string str = std::string(bytes1.begin(), bytes1.end());
  DNS_Header_t *dns_header = parse_header((char *)str.c_str());
  uint16_t RESERVED_FLAG = 0b0000000001000000;
  if ((dns_header->flags & RESERVED_FLAG) != 0) {
    printf("Error:Invalid packet");
  }

  std::cout << "Header is: " << std::hex << htobe16(dns_header->id) << "\n";
  std::cout << "Question num is: " << std::hex
            << htobe16(dns_header->question_count) << "\n";
  std::cout << "Answer num is: " << std::hex
            << htobe16(dns_header->answer_count) << "\n";
  std::cout << "Nameserver num is: " << htobe16(dns_header->authorities_count)
            << "\n";
  std::cout << "Additional num is: " << htobe16(dns_header->additional_count)
            << "\n";
  if (htobe16(dns_header->question_count) != 1) {
    std::cout << "Invalid packet"
              << "\n";
    std::cout << "Exiting..."
              << "\n";
    return;
  }
  size_t qn_count = htobe16(dns_header->question_count);
  size_t tot_qn_size = 0;
  for (size_t i = 0; i < qn_count; i++) {
    DNS_Question_t *dns_question =
        (DNS_Question_t *)malloc(sizeof(DNS_Question_t));
    size_t qn_size =
        parse_question((char *)str.c_str() + sizeof(DNS_Header_t) + tot_qn_size,
                       dns_question, (char *)str.c_str());
    tot_qn_size += qn_size;
    std::cout << "Question domain name is: " << dns_question->q_name << "\n";
    std::cout << "Question type is: " << dns_type_strings[dns_question->q_type]
              << "\n";
    std::cout << "Question class is: "
              << dns_class_strings[dns_question->q_class] << "\n";
  }
  std::cout << "Tot qn size = " << std::dec << tot_qn_size << "\n";
  std::cout << "Tot qn size + header size = " << std::dec
            << tot_qn_size + sizeof(DNS_Header_t) << "\n";
  for (size_t i = 0; i < htobe16(dns_header->answer_count); i++) {
    auto dns_answer = (DNS_Resource_t *)malloc(sizeof(DNS_Resource_t));
    parse_answer((char *)str.c_str() + sizeof(DNS_Header_t) + tot_qn_size,
                 dns_answer, (char *)str.c_str());
    std::cout << "Answer name = " << dns_answer->r_name << "\n";
    std::cout << "Answer type = "
              << dns_resource_type_strings[dns_answer->r_type] << "\n";
    std::cout << "Answer class = "
              << dns_resource_class_strings[dns_answer->r_class] << "\n";
    std::cout << "Answer rdlength = " << dns_answer->r_rdlength << "\n";
    std::cout << "Answer ttl = " << dns_answer->r_ttl << "\n";
    std::cout << "Answer data = " << dns_answer->r_data << "\n";
  }
}

int main(void) { test_dns_header_parse(); }
