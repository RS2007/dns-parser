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
      "0000000000000020920000c2100000084f300001e000000645000010000000590c56c676"
      "f6f676602756473716d64737f686d237e646d24657f6c6364100d6f6363037e69616d6f6"
      "4656c676f6f676d01356d24657f6c636d237e6b015007e00000010006000630c130c1347"
      "375677d2375780b0009c00000010005000130c004756e630073676a7f6d6603756369667"
      "275637265677b046f6270740f6d657374046f627074072005f10000010005000c00c1000"
      "c100007627f63016c6c696a7f6d6704727f60707573770100010002000100008186da75a"
      "93fd0020cc5300c6008a0c10008a0c328c11d3000091333f0000540080a15a749f6148bf"
      "39cfe49c07"); /* std::vector<char> bytes1 =
                      * HexToBytes("ec2e98e9046b34e894fa3f5e08004500006b030400003e11f7c4c0a80001c0a80068003581c300577fa37baf818000010001000000010f7a2d7034322d696e7374616772616d046331307209696e7374616772616d03636f6d0000010001c00c000100010000000c00049df017ae0000290200000000000000");
                      */
  /* std::string str = std::string(bytes1.begin(), bytes1.end()); */
  unsigned char resp[] = {
      0xfc, 0x9d, 0x81, 0x80, 0x00, 0x01, 0x00, 0x06, 0x00, 0x02, 0x00, 0x02,
      0x03, 'c',  'd',  'n',  0x07, 's',  's',  't',  'a',  't',  'i',  'c',
      0x03, 'n',  'e',  't',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
      0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 'f',  0x00, 0x02, 0xc0, 0x10, 0xc0,
      0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 'f',  0x00, 0x04, 'h',
      0x10, 'g',  0xcc, 0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
      'f',  0x00, 0x04, 'h',  0x10, 'k',  0xcc, 0xc0, 0x10, 0x00, 0x01, 0x00,
      0x01, 0x00, 0x00, 0x00, 'f',  0x00, 0x04, 'h',  0x10, 'h',  0xcc, 0xc0,
      0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 'f',  0x00, 0x04, 'h',
      0x10, 'j',  0xcc, 0xc0, 0x10, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
      'f',  0x00, 0x04, 'h',  0x10, 'i',  0xcc, 0xc0, 0x10, 0x00, 0x02, 0x00,
      0x01, 0x00, 0x00, 0x99, 'L',  0x00, 0x0b, 0x08, 'c',  'f',  '-',  'd',
      'n',  's',  '0',  '2',  0xc0, 0x10, 0xc0, 0x10, 0x00, 0x02, 0x00, 0x01,
      0x00, 0x00, 0x99, 'L',  0x00, 0x0b, 0x08, 'c',  'f',  '-',  'd',  'n',
      's',  '0',  '1',  0xc0, 0x10, 0xc0, 0xa2, 0x00, 0x01, 0x00, 0x01, 0x00,
      0x00, 0x99, 'L',  0x00, 0x04, 0xad, 0xf5, ':',  '5',  0xc0, 0x8b, 0x00,
      0x01, 0x00, 0x01, 0x00, 0x00, 0x99, 'L',  0x00, 0x04, 0xad, 0xf5, ';',
      0x04};
  std::string str = std::string(resp, resp + sizeof(resp));
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
  size_t tot_an_size = 0;
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
    parse_answer((char *)str.c_str() + sizeof(DNS_Header_t) + tot_qn_size +
                     tot_an_size,
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
