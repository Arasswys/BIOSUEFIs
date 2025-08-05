UEFIRIP

("UEFI Rest In Peace") — çalıştıktan sonra sistem geri gelmiyor.

Type:Ring -2 Wiper

Brick Type:Hard Brick

Action, Description, Effect, Emoji
Administrator Privilege Check: "Checks administrator privileges and restarts the script with elevated privileges if necessary (run_as_admin, is_admin).","Provides full system access, which is critical for destructive actions.",🔑
Command Obfuscation: "Obscures commands with Base64, XOR, and random data padding (obfuscate_string, deobfuscate_string)..",Hides malicious commands from antivirus or analysis tools.,🥷
Security Disablement: "Disables Windows Defender and AMSI (security_bypass). Turns off real-time protection, scanning, and other security features with PowerShell commands.","Weakens system defenses, making code more difficult to detect.",🛡️❌
EFI Partition Check: Checks the existence of an EFI partition (check_efi_partition). If the EFI partition exists, it mounts to drive X:. Prepares access to the EFI partition for target boot files. 💾
Creating Bootloader Files: "Creates fake bootloader files (bootmgfw.efi, bootx64.efi, etc.) in the EFI partition (create_bootloaders). Each file contains 1 MB of random data." "Disrupts the boot process, preventing the system from starting." 🚫💿
NVRAM Corruption: Writes fake data files to the EFI variable store (create_efi_vars). Each file contains 5 MB of random data. It corrupts UEFI settings, rendering the boot menu inoperable. 🧠💥
Firmware Update: "Creates fake BIOS, SPI flash, and Intel ME files (create_firmware_updates, update_firmware_vars). Each file contains 15 MB of random data." It can corrupt the firmware, preventing the motherboard from starting. 🖥️🔥
Registry Update: "Floods the system, BIOS, and Windows NT registry keys with random data (update_firmware_registry, update_registry). Corrupts the system configuration and scrambles services and boot settings." 📝🗑️
COM Object Creation: Registers fake COM objects with random CLSIDs (create_com_objects). Confuses system processes, hiding potentially malicious services. 🕳️
BCD and Boot: Breaking the Boot Chain: Creates fake BCD entries and changes the boot loader path (create_boot_chain). Disrupts the boot order, preventing Windows from starting. 🔗❌
MBR Corruption: On non-EFI systems, writes random data to the MBR and erases the disk with diskpart (repair_mbr). Makes booting impossible on older systems. 💽🗑️
Disk Data Corruption: "Writes random data to disk sectors (e.g., 10,000 sectors, ~5 MB) and creates fake data files (repair_disk_data). It corrupts the file system and disk structures, causing data loss. 💾💥
System File Updating: "Replaces critical system files (e.g., ntoskrnl.exe, winload.efi) with random data (update_system_files). It affects the Windows kernel and boot components. 🖥️🚫
Driver Installation: Creates a fake driver file (driver_update*.sys) and registers it as a service (install_driver). It can add malicious drivers to the system, gaining persistent access. 🔌
Boot File Creation: Creates boot.ini and bootsect.bak files with random data (create_boot_files). It corrupts the old boot configuration. 📁🗑️
Windows Update Files: Creates fake Windows Update files (15 MB) (create_update_files). "Confuses the update mechanism and fills up disk space." 📥❌
File System Metadata: Creates fake file system files and checks NTFS metadata (repair_filesystem_metadata). "Compromises file system consistency." 🗄️💥
System Reboot: Reboots the system (system_reboot). "Applies changes and may render the system unbootable." 🔄
Dynamic Command Mutation: Randomly modifies commands (mutate_command) and executes encrypted commands. "Makes detection difficult and erases disk and boot structures." 🧬
GUI Interface: Creates a graphical interface (create_gui) with Tkinter. Presents the user with a fake "Hardware Repair Tool." Tricks the user to initiate malicious actions., 🖼️😈

Damaged Ring Levels: Usermode, Kernel, Hypervisor, Firmware, BIOS, UEFI, SPI Flash and more.




