# Branch Predictors & ASLR
**Author: Byte Reaper**

## Description
This repository contains research C implementation that demonstrates concepts related to branch predictors, speculative execution, and cache-based side channels in the context of address space layout randomization (ASLR).  

## Requirements :
```
Linux x86_64
GCC 
CPU that supports BTB
```

## Build :
```
gcc btb.c -o BTB
./BTB
```
## Quick output (examples):
```
[+] check  System Security for Check branch predictors...
[+] Sleep Success.
[-] Not Detect Single Thread Indirect Branch Predictors.
[-] Not Detect Indirect Branch Restricted Speculation
[-] Not Detect Speculative Store Bypass Disable .
[+] Detect L1D_FLUSH.
[+] Detect MD_CLEAR.
[-] Not Detect IA32_ARCH_CAPABILITIES.
[+] Result Detect Branch predictors : 
[+] Detect Branch predictors
[+] Get Address  victimValue() function Success.
...
```
## References : 
- intel doc MSR / cpuid : https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/cpuid-enumeration-and-architectural-msrs.html


- jump over aslr : https://www.cs.ucr.edu/~nael/pubs/micro16.pdf


## License : 
MIT