import subprocess

subprocess.run("g++ -O3 -o dns_test dns_test.cpp",shell=True,check=True)
subprocess.run("./dns_test",shell=True,check=True)
