# Cryptography-RSA-Checksum
This project verifies the Digital Signature and the checksum of the sent packet of data using SHA-256.

Using the included files, I have created a UDP server that handles the following criteria:
1. Verify the structural integrity of the packet
2. Verify the packet has a valid digital signature
• Failing this, the server should write to a log file in the root directory of the project in a log file named
verification_failures.log
3. Verify checksums are being sent correctly
• Failing this, the server should write to a log file in the root directory of the project in a log file named
checksum_failures.log
4. Introduce an artificial “delay” for writing to the log file, the duration will be passed as a command line
argument (in seconds)
