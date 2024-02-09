#include "dns.h"
#include <algorithm>
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

  std::vector<char> bytes2 =
      HexToBytes("4c76010000010000000000010c74696d65736f66696e6469610a696e64696"
                 "174696d657303636f6d00000100010000290200000000000000");

  std::vector<char> bytes3 =
      HexToBytes("629f8180000100010000000103637365046969746d02616302696e0000010"
                 "001c00c0001000100001f9600040a0608020000290200000000000000");

  std::vector<char> bytes4 = HexToBytes(
      "00c88b57ec40ec2e98e9046b08004500004b527e40004011802f0a2a52f10a1800c2 "
      "e36400350037875137920100000100000000000106636c69656e740764726f70626"
      "f7803636f6d00000100010000290200000000000000");

  std::vector<char> bytes5 = HexToBytes(
      "ec2e98e9046b34e894fa3f5e08004500006b030400003e11f7c4c0a80001c0a80068 "
      "003581c300577fa37baf818000010001000000010f7a2d7034322d696e7374616772 "
      "616d046331307209696e7374616772616d03636f6d0000010001c00c00010001000"
      "0000c00049df017ae0000290200000000000000");

  std::vector<char> bytes6 = HexToBytes(
      "a0208180000100010000000105666f6e74730a676f6f676c656170697303636f6d00"
      "00010001c00c00010001000000ae00048efab64a0000290200000000000000");

  /* std::vector<char> bytes1 =
   * HexToBytes("ec2e98e9046b34e894fa3f5e08004500006b030400003e11f7c4c0a80001c0a80068003581c300577fa37baf818000010001000000010f7a2d7034322d696e7374616772616d046331307209696e7374616772616d03636f6d0000010001c00c000100010000000c00049df017ae0000290200000000000000");
   */
  std::string pack2 = std::string(bytes2.begin(), bytes2.end());
  std::string pack3 = std::string(bytes3.begin(), bytes3.end());
  std::string pack4 = std::string(bytes4.begin(), bytes4.end());
  std::string pack5 = std::string(bytes5.begin(), bytes5.end());
  std::string pack6 = std::string(bytes6.begin(), bytes6.end());
  unsigned char resp1[] = {
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

  unsigned char resp2[] = {
      0x4a, 0xf0, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x03, 'w',  'w',  'w',  0x05, 's',  'k',  'y',  'p',  'e',  0x03, 'c',
      'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00,
      0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x1c, 0x07, 'l',  'i',  'v',  'e',
      'c',  'm',  's',  0x0e, 't',  'r',  'a',  'f',  'f',  'i',  'c',  'm',
      'a',  'n',  'a',  'g',  'e',  'r',  0x03, 'n',  'e',  't',  0x00, 0xc0,
      0x42, 0x00, 0x02, 0x00, 0x01, 0x00, 0x01, 0xd5, 0xd3, 0x00, 0x11, 0x01,
      0x67, 0x0c, 'g',  't',  'l',  'd',  '-',  's',  'e',  'r',  'v',  'e',
      'r',  's',  0xc0, 0x42};
  unsigned char resp3[] = {
      0x06, 0x25, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03,
      0x63, 0x6f, 0x6d, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x0c, 0x00,
      0x10, 0x00, 0x01, 0x00, 0x01, 0x51, 0x3d, 0x00, 0x23, 0x15, 0x76,
      0x3d, 0x73, 0x70, 0x66, 0x31, 0x20, 0x72, 0x65, 0x64, 0x69, 0x72,
      0x65, 0x63, 0x74, 0x3d, 0x5f, 0x73, 0x70, 0x66, 0x2e, 0x0c, 0x66,
      0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x2e, 0x63, 0x6f, 0x6d};

  std::string pack1 = std::string(resp1, resp1 + sizeof(resp1));
  std::string pack7 = std::string(resp2, resp2 + sizeof(resp2));
  std::string pack8 = std::string(resp3, resp3 + sizeof(resp3));
  std::vector<std::string> packets = {pack1, pack2, pack3, pack4,
                                      pack5, pack6, pack7, pack8};
  auto index = 1;
  for (auto str : packets) {
    std::cout << "Packet " << index++ << "\n";
    DNS_Header_t *dns_header = parse_header((char *)str.c_str());
    uint16_t RESERVED_FLAG = 0b0000000001000000;
    if ((dns_header->flags & RESERVED_FLAG) != 0) {
      printf("Error:Invalid packet");
    }

#ifdef DEBUG
    std::cout << "Header is: " << std::hex << htobe16(dns_header->id) << "\n";
    std::cout << "Question num is: " << std::hex
              << htobe16(dns_header->question_count) << "\n";
    std::cout << "Answer num is: " << std::hex
              << htobe16(dns_header->answer_count) << "\n";
    std::cout << "Nameserver num is: " << htobe16(dns_header->authorities_count)
              << "\n";
    std::cout << "Additional num is: " << htobe16(dns_header->additional_count)
              << "\n";
#endif
    if (htobe16(dns_header->question_count) != 1) {
      std::cout << "Invalid packet"
                << "\n";
      std::cout << "Exiting..."
                << "\n";
      continue;
    }
    size_t qn_count = htobe16(dns_header->question_count);
    size_t tot_qn_size = 0;
    size_t tot_an_size = 0;
    for (size_t i = 0; i < qn_count; i++) {
      DNS_Question_t *dns_question =
          (DNS_Question_t *)malloc(sizeof(DNS_Question_t));
      size_t qn_size = parse_question((char *)str.c_str() +
                                          sizeof(DNS_Header_t) + tot_qn_size,
                                      dns_question, (char *)str.c_str());
      tot_qn_size += qn_size;
      std::cout << "Question domain name is: " << dns_question->q_name << "\n";
#ifdef DEBUG
      std::cout << "Question type is: "
                << dns_type_strings[dns_question->q_type] << "\n";
      std::cout << "Question class is: "
                << dns_class_strings[dns_question->q_class] << "\n";
#endif
    }
#ifdef DEBUG
    std::cout << "Tot qn size = " << std::dec << tot_qn_size << "\n";
    std::cout << "Tot qn size + header size = " << std::dec
              << tot_qn_size + sizeof(DNS_Header_t) << "\n";
#endif
    for (size_t i = 0; i < std::min((int)htobe16(dns_header->answer_count), 1);
         i++) {
      auto dns_answer = (DNS_Resource_t *)malloc(sizeof(DNS_Resource_t));
      parse_answer((char *)str.c_str() + sizeof(DNS_Header_t) + tot_qn_size +
                       tot_an_size,
                   dns_answer, (char *)str.c_str());
      std::cout << "Answer name = " << dns_answer->r_name << "\n";
#ifdef DEBUG
      std::cout << "Answer type = "
                << dns_resource_type_strings[dns_answer->r_type] << "\n";
      std::cout << "Answer class = "
                << dns_resource_class_strings[dns_answer->r_class] << "\n";
      std::cout << "Answer rdlength = " << dns_answer->r_rdlength << "\n";
      std::cout << "Answer ttl = " << dns_answer->r_ttl << "\n";
#endif

      std::cout << "Answer data = " << dns_answer->r_data << "\n";
    }
  }
}

int main(void) { test_dns_header_parse(); }
