# Secure File Transfer (C++ / Windows)

A robust and secure file transfer utility built using C++ and OpenSSL, designed specifically for Windows systems. It allows encrypted file transfers over TCP sockets with integrity verification and resume support.

**Note:** This is a single executable that can operate in both sender and receiver modes.

## Features

- 🔐 **AES-256 Encryption** with unique IV per chunk
- ✅ **SHA-256 checksum** for integrity validation
- 🔑 **Authentication code** for secure pairing
- 🔄 **Transfer resume support** (partially implemented)
- 📦 **Chunked file transmission** with progress tracking
- ⚙️ **Cross-component structure** for reusability and scalability
- 🪟 **Optimized for Windows (Winsock)**

---

## Getting Started

### Prerequisites

- Windows OS
- Visual Studio 2022 or compatible
- [OpenSSL for Windows](https://slproweb.com/products/Win32OpenSSL.html) installed

Ensure the following libraries are linked:

```cpp
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
```

---

## Build Instructions

1. Clone or download the repository.
2. Open the `.cpp` file in Visual Studio.
3. Link the required OpenSSL libraries (`libssl`, `libcrypto`) in project settings.
4. Build in `Release` or `Debug` mode.

---

## Usage

### Setting Visual Studio Environment
```bash
C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
```
(This is usually the path but you might need to alter this according to your path)

### Compilation of the Code 
```bash
cl /EHsc /std:c++17 secure_transfer.cpp /I"C:\Program Files\OpenSSL-Win64\include" /link /LIBPATH:"C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD" libssl.lib libcrypto.lib ws2_32.lib
```
(You might need to alter the path of the OpenSSL to run the code)

### Running the Program

#### Sender Mode

```bash
secure_transfer.exe send <filepath> [port]
```

**Example:**

```bash
secure_transfer.exe send "C:\Users\User\Desktop\file.txt" 8888
```

**Steps:**
1. Run the command above
2. Enter an encryption password when prompted
3. Note the 6-digit authentication code displayed
4. Share this code with the receiver
5. Wait for receiver to connect

#### Receiver Mode

```bash
secure_transfer.exe receive <server_ip> <auth_code> <save_directory> [port]
```

**Example:**

```bash
secure_transfer.exe receive 192.168.1.10 123456 "C:\Users\User\Downloads" 8888
```

**Steps:**
1. Get the authentication code from the sender
2. Run the command above with sender's IP address
3. Enter the same encryption password used by sender
4. Wait for file transfer to complete

### Finding IP Address
On the sender's computer, run:
```bash
ipconfig
```
Look for "IPv4 Address" under your network adapter (usually starts with 192.168.x.x)

---

## Security Highlights

- Password-derived AES-256 encryption key (PBKDF2-HMAC-SHA256)
- Unique IVs per chunk to ensure data confidentiality
- SHA-256 checksums to verify integrity
- Zero plaintext transmission over network
- Authentication code challenge to prevent unauthorized connections

---

## Directory Structure

All logic is contained in `secure_transfer.cpp`, including:

- `CryptoUtils`: Handles encryption/decryption and hashing.
- `NetworkUtils`: Manages socket operations and protocols.
- `FileTransferSender`: Manages file sending logic.
- `FileTransferReceiver`: Handles receiving and reconstruction.
- `main()`: Entry point and argument handler.

---

## Limitations

- Supports files up to **20 MB**
- Only one file per transfer session
- Designed and tested for **Windows only**
- No GUI — CLI only

---

## Future Improvements

- Add GUI wrapper using Qt or WinForms
- Resume interrupted transfers
- Cross-platform support (Linux/Unix)
- Multi-file or folder transfer
- Logging and audit trail

---

## Author

Developed by Slok Regmi , Sunil Giri , Laxman Khatri
Feel free to contribute or suggest enhancements!

---

## License

This project is licensed under the MIT License. See `LICENSE` file for details.