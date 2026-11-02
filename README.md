Title: iNFERRE HWDetectNG hwdetectng.sys physical memory access

Vendor: iNFERRE
Product: HWDetectNG
Component: hwdetectng.sys
SHA-256: 2f8b68de1e541093f2d4525a0d02f36d361cd69ee8b1db18e6dd064af3856f4f
MD5: 2a5fb925125af951bd76c00579d61666
SHA-1: 75dd52e28c40cd22e38ae2a74b52eb0cddfcb2c4
Size: 23112 bytes
PE timestamp: 2009-01-10 10:54:33 UTC
FileVersion: 2.8 built by: WinDDK
ProductVersion: 2.8
OriginalFilename: hwdetectng.sys
Version-resource product name: hwdetectng.sys
Authenticode status: Valid
Signer: E=info@inferre.de, CN=iNFERRE, O=iNFERRE, C=DE
Certificate thumbprint: 20FF6F1452AD2F12EC75A92675B93F80794B638F
Certificate not before: 2009-01-08 12:13:16 UTC
Certificate not after: 2010-01-08 12:13:16 UTC
Device: \\.\HwDetectNG
PDB: d:\projectsnet\hwdetectngdlltest\driverx86ia64\objfre_wnet_amd64\amd64\HwDetectNG.pdb

CVE:

Description:
hwdetectng.sys in iNFERRE HWDetectNG FileVersion 2.8 built by: WinDDK (SHA-256 2f8b68de1e541093f2d4525a0d02f36d361cd69ee8b1db18e6dd064af3856f4f) passes a caller-supplied 32-bit physical address to MmMapIoSpace on IOCTL 0x80102070 (METHOD_BUFFERED) after clearing the high 32 bits, maps a caller-supplied length as non-cached, accepts only an access width of 1, 2, or 4, multiplies that width by a caller-supplied count, does not validate the address range, and copies caller-supplied bytes into that mapping, which allows a local user to read and write arbitrary physical memory and locally escalate privileges via \\.\HwDetectNG. IOCTL 0x80102058 reads those mapped bytes back into the start of the output buffer. The Authenticode status is Valid, signed by E=info@inferre.de, CN=iNFERRE, O=iNFERRE, C=DE. On 2026-11-03, on an isolated Windows 10 Enterprise LTSC 2021 virtual machine (10.0.19044.7807), an administrator loaded this file and the service started. The administrator locked one of its own pages at physical address 0x19648000, wrote 0x3C as the first byte, and did not send either IOCTL. Local account aida-low, a member of Users and not a member of Administrators, opened \\.\HwDetectNG, sent IOCTL 0x80102058 for that address with width 1 and count 1, and read 0x3C. That account then sent IOCTL 0x80102070, wrote 0x5A, and read 0x5A back through IOCTL 0x80102058, then wrote 0xA5 and read 0xA5 back the same way. The administrator read the first byte of that physical page and saw 0x5A, then 0xA5. The test did not show a crash. The device security descriptor was O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW). Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA.

Suggested fix: on IOCTL 0x80102070 and IOCTL 0x80102058, use only a physical address chosen inside the driver, and limit access to \\.\HwDetectNG to Administrators and SYSTEM.
