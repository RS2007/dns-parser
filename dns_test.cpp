#include "dns.h"
#include <cstring>
#include <iostream>
#include <vector>

std::vector<char> HexToBytes(const std::string& hex) {
  std::vector<char> bytes;

  for (unsigned int i = 0; i < hex.length(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    char byte = (char) strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }

  return bytes;
}

void test_dns_header_parse(){
	std::vector<char> bytes1 = HexToBytes("4c76010000010000000000010c74696d65736f66696e6469610a696e64696174696d657303636f6d00000100010000290200000000000000");
	std::string str = std::string(bytes1.begin(),bytes1.end());
	DNS_Header_t* dns_header = parse_header(str.c_str());
	std::cout << "Header is: " << std::hex << htobe16(dns_header->id) << "\n";
	std::cout << "Question num is: " << std::hex << htobe16(dns_header->question_count) << "\n";
	std::cout << "Answer num is: " << std::hex << htobe16(dns_header->answer_count) << "\n";
	DNS_Question_t* dns_question = (DNS_Question_t*)malloc(sizeof(DNS_Question_t));
	size_t qn_size = parse_question(str.c_str(),dns_question);
	std::cout << "Question domain name is: " << dns_question->q_name << "\n";
	std::cout << "Question type is: " << dns_type_strings[dns_question->q_type] << "\n";
	std::cout << "Question class is: " << dns_class_strings[dns_question->q_class] << "\n";
}

int main(void){
	test_dns_header_parse();
}
