#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <memory>
#include <thread>
#include <chrono>
#include <random>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <mutex>
#include <condition_variable>

// Windows-specific headers
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <conio.h>

// OpenSSL headers (requires OpenSSL installation)
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/md5.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

namespace fs = std::filesystem;

constexpr int DEFAULT_PORT = 8888;
constexpr int MAX_FILE_SIZE = 20 * 1024 * 1024; // 20 MB
constexpr int CHUNK_SIZE = 8192; // 8KB chunks
constexpr int MAX_RETRIES = 3;
constexpr int TIMEOUT_SECONDS = 30;

// Protocol message types
enum class MessageType : uint8_t {
    AUTH_REQUEST = 1,
    AUTH_RESPONSE = 2,
    FILE_INFO = 3,
    FILE_DATA = 4,
    FILE_COMPLETE = 5,
    ERROR_MSG = 6,
    RESUME_REQUEST = 7,
    CHECKSUM_VERIFY = 8
};

// Error codes
enum class ErrorCode : uint8_t {
    SUCCESS = 0,
    AUTH_FAILED = 1,
    FILE_NOT_FOUND = 2,
    NETWORK_ERROR = 3,
    ENCRYPTION_ERROR = 4,
    CHECKSUM_MISMATCH = 5,
    FILE_TOO_LARGE = 6,
    PERMISSION_DENIED = 7
};

// Message structure for protocol
struct Message {
    MessageType type;
    uint32_t length;
    std::vector<uint8_t> data;
};

// File information structure
struct FileInfo {
    std::string filename;
    uint64_t size;
    std::string checksum;
    std::vector<uint8_t> iv; // Initialization vector for AES
};

// Transfer state for resume capability
struct TransferState {
    uint64_t bytesTransferred;
    std::string tempFilePath;
    FileInfo fileInfo;
    bool isComplete;
};

class CryptoUtils {
public:
    static std::string generateAuthCode() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(100000, 999999);
        return std::to_string(dis(gen));
    }

    static std::vector<uint8_t> generateKey(const std::string& password) {
        std::vector<uint8_t> key(32); // 256-bit key
        PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                         nullptr, 0, 10000, EVP_sha256(), 32, key.data());
        return key;
    }

    static std::vector<uint8_t> generateIV() {
        std::vector<uint8_t> iv(16); // 128-bit IV
        RAND_bytes(iv.data(), 16);
        return iv;
    }

    // Generate a unique IV for each chunk by combining base IV with counter
    static std::vector<uint8_t> generateChunkIV(const std::vector<uint8_t>& baseIV, uint64_t chunkCounter) {
        std::vector<uint8_t> chunkIV = baseIV;
        
        // XOR the counter into the last 8 bytes of the IV
        uint64_t counter = chunkCounter;
        for (int i = 0; i < 8; i++) {
            chunkIV[8 + i] ^= (counter >> (i * 8)) & 0xFF;
        }
        
        return chunkIV;
    }

    static std::vector<uint8_t> encryptData(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }

        std::vector<uint8_t> encrypted(data.size() + AES_BLOCK_SIZE);
        int len;
        int ciphertext_len;

        if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        encrypted.resize(ciphertext_len);
        return encrypted;
    }

    static std::vector<uint8_t> decryptData(const std::vector<uint8_t>& encrypted,
                                           const std::vector<uint8_t>& key,
                                           const std::vector<uint8_t>& iv) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return {};

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }

        std::vector<uint8_t> decrypted(encrypted.size() + AES_BLOCK_SIZE);
        int len;
        int plaintext_len;

        if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted.data(), encrypted.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return {};
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);
        decrypted.resize(plaintext_len);
        return decrypted;
    }

    static std::string calculateSHA256(const std::vector<uint8_t>& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, data.data(), data.size());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    static std::string calculateFileChecksum(const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) return "";

        std::vector<uint8_t> buffer(CHUNK_SIZE);
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount() > 0) {
            SHA256_Update(&sha256, buffer.data(), file.gcount());
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }
};

class NetworkUtils {
public:
    static bool initializeWinsock() {
        WSADATA wsaData;
        return WSAStartup(MAKEWORD(2, 2), &wsaData) == 0;
    }

    static void cleanupWinsock() {
        WSACleanup();
    }

    static bool sendMessage(SOCKET sock, const Message& msg) {
        // Send message header
        uint8_t header[5];
        header[0] = static_cast<uint8_t>(msg.type);
        *reinterpret_cast<uint32_t*>(&header[1]) = htonl(msg.length);

        if (send(sock, reinterpret_cast<char*>(header), 5, 0) != 5) {
            return false;
        }

        // Send message data
        if (msg.length > 0) {
            size_t sent = 0;
            while (sent < msg.data.size()) {
                int result = send(sock, reinterpret_cast<const char*>(msg.data.data() + sent), 
                                static_cast<int>(msg.data.size() - sent), 0);
                if (result <= 0) return false;
                sent += result;
            }
        }
        return true;
    }

    static bool receiveMessage(SOCKET sock, Message& msg) {
        // Receive message header
        uint8_t header[5];
        if (recv(sock, reinterpret_cast<char*>(header), 5, MSG_WAITALL) != 5) {
            return false;
        }

        msg.type = static_cast<MessageType>(header[0]);
        msg.length = ntohl(*reinterpret_cast<uint32_t*>(&header[1]));

        // Receive message data
        if (msg.length > 0) {
            msg.data.resize(msg.length);
            size_t received = 0;
            while (received < msg.length) {
                int result = recv(sock, reinterpret_cast<char*>(msg.data.data() + received), 
                                static_cast<int>(msg.length - received), 0);
                if (result <= 0) return false;
                received += result;
            }
        }
        return true;
    }

    static bool setSocketTimeout(SOCKET sock, int timeoutSeconds) {
        DWORD timeout = timeoutSeconds * 1000;
        return setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, 
                         reinterpret_cast<char*>(&timeout), sizeof(timeout)) == 0;
    }
};

class FileTransferSender {
private:
    SOCKET serverSocket;
    std::string authCode;
    std::vector<uint8_t> encryptionKey;
    bool isRunning;

public:
    FileTransferSender() : serverSocket(INVALID_SOCKET), isRunning(false) {}

    ~FileTransferSender() {
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
        }
    }

    bool startServer(int port = DEFAULT_PORT) {
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket == INVALID_SOCKET) {
            std::cerr << "Failed to create socket\n";
            return false;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(port);

        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, 
                  reinterpret_cast<char*>(&opt), sizeof(opt));

        if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Failed to bind socket\n";
            return false;
        }

        if (listen(serverSocket, 1) == SOCKET_ERROR) {
            std::cerr << "Failed to listen on socket\n";
            return false;
        }

        isRunning = true;
        std::cout << "Server listening on port " << port << std::endl;
        return true;
    }

    bool sendFile(const std::string& filepath, const std::string& password) {
        if (!fs::exists(filepath)) {
            std::cerr << "File not found: " << filepath << std::endl;
            return false;
        }

        auto fileSize = fs::file_size(filepath);
        if (fileSize > MAX_FILE_SIZE) {
            std::cerr << "File too large (max 20MB): " << filepath << std::endl;
            return false;
        }

        // Generate auth code and encryption key
        authCode = CryptoUtils::generateAuthCode();
        encryptionKey = CryptoUtils::generateKey(password);

        std::cout << "Authorization Code: " << authCode << std::endl;
        std::cout << "Waiting for receiver to connect..." << std::endl;

        // Accept connection
        SOCKET clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Failed to accept connection\n";
            return false;
        }

        NetworkUtils::setSocketTimeout(clientSocket, TIMEOUT_SECONDS);

        bool success = false;
        try {
            success = handleFileTransfer(clientSocket, filepath);
        } catch (const std::exception& e) {
            std::cerr << "Transfer error: " << e.what() << std::endl;
        }

        closesocket(clientSocket);
        return success;
    }

private:
    bool handleFileTransfer(SOCKET clientSocket, const std::string& filepath) {
        // Wait for auth request
        Message authRequest;
        if (!NetworkUtils::receiveMessage(clientSocket, authRequest) || 
            authRequest.type != MessageType::AUTH_REQUEST) {
            return false;
        }

        std::string receivedCode(authRequest.data.begin(), authRequest.data.end());
        Message authResponse;
        authResponse.type = MessageType::AUTH_RESPONSE;

        if (receivedCode == authCode) {
            authResponse.length = 1;
            authResponse.data.push_back(static_cast<uint8_t>(ErrorCode::SUCCESS));
        } else {
            authResponse.length = 1;
            authResponse.data.push_back(static_cast<uint8_t>(ErrorCode::AUTH_FAILED));
            NetworkUtils::sendMessage(clientSocket, authResponse);
            return false;
        }

        if (!NetworkUtils::sendMessage(clientSocket, authResponse)) {
            return false;
        }

        // Prepare file info
        FileInfo fileInfo;
        fileInfo.filename = fs::path(filepath).filename().string();
        fileInfo.size = fs::file_size(filepath);
        fileInfo.checksum = CryptoUtils::calculateFileChecksum(filepath);
        fileInfo.iv = CryptoUtils::generateIV();

        // Send file info
        Message fileInfoMsg;
        fileInfoMsg.type = MessageType::FILE_INFO;
        
        std::string fileInfoStr = fileInfo.filename + "|" + 
                                 std::to_string(fileInfo.size) + "|" + 
                                 fileInfo.checksum + "|";
        
        std::vector<uint8_t> fileInfoData(fileInfoStr.begin(), fileInfoStr.end());
        fileInfoData.insert(fileInfoData.end(), fileInfo.iv.begin(), fileInfo.iv.end());
        
        fileInfoMsg.length = static_cast<uint32_t>(fileInfoData.size());
        fileInfoMsg.data = fileInfoData;

        if (!NetworkUtils::sendMessage(clientSocket, fileInfoMsg)) {
            return false;
        }

        // Send file data
        return sendFileData(clientSocket, filepath, fileInfo);
    }

    bool sendFileData(SOCKET clientSocket, const std::string& filepath, const FileInfo& fileInfo) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to open file: " << filepath << std::endl;
            return false;
        }

        std::vector<uint8_t> buffer(CHUNK_SIZE);
        uint64_t totalSent = 0;
        uint64_t chunkCounter = 0;

        std::cout << "Sending file: " << fileInfo.filename << " (" << fileInfo.size << " bytes)" << std::endl;

        while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount() > 0) {
            size_t bytesRead = file.gcount();
            buffer.resize(bytesRead);

            // Generate unique IV for this chunk
            auto chunkIV = CryptoUtils::generateChunkIV(fileInfo.iv, chunkCounter);

            // Encrypt chunk with unique IV
            auto encryptedChunk = CryptoUtils::encryptData(buffer, encryptionKey, chunkIV);
            if (encryptedChunk.empty()) {
                std::cerr << "Encryption failed" << std::endl;
                return false;
            }

            // Send chunk counter first, then encrypted data
            Message dataMsg;
            dataMsg.type = MessageType::FILE_DATA;
            
            // Prepend chunk counter to the encrypted data
            std::vector<uint8_t> chunkData(8); // 8 bytes for counter
            *reinterpret_cast<uint64_t*>(chunkData.data()) = chunkCounter;
            chunkData.insert(chunkData.end(), encryptedChunk.begin(), encryptedChunk.end());
            
            dataMsg.length = static_cast<uint32_t>(chunkData.size());
            dataMsg.data = chunkData;

            if (!NetworkUtils::sendMessage(clientSocket, dataMsg)) {
                std::cerr << "Failed to send data chunk" << std::endl;
                return false;
            }

            totalSent += bytesRead;
            chunkCounter++;
            
            // Progress indicator
            int progress = (int)((totalSent * 100) / fileInfo.size);
            std::cout << "\rProgress: " << progress << "% (" << totalSent << "/" << fileInfo.size << " bytes)" << std::flush;

            buffer.resize(CHUNK_SIZE);
        }

        std::cout << std::endl;

        // Send completion message
        Message completeMsg;
        completeMsg.type = MessageType::FILE_COMPLETE;
        completeMsg.length = 0;

        if (!NetworkUtils::sendMessage(clientSocket, completeMsg)) {
            return false;
        }

        std::cout << "File transfer completed successfully!" << std::endl;
        return true;
    }
};

class FileTransferReceiver {
private:
    SOCKET clientSocket;
    std::vector<uint8_t> encryptionKey;
    std::string saveDirectory;

public:
    FileTransferReceiver() : clientSocket(INVALID_SOCKET) {}

    ~FileTransferReceiver() {
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
        }
    }

    bool connectToSender(const std::string& serverIP, int port = DEFAULT_PORT) {
        clientSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (clientSocket == INVALID_SOCKET) {
            std::cerr << "Failed to create socket\n";
            return false;
        }

        sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr) <= 0) {
            std::cerr << "Invalid server IP address\n";
            return false;
        }

        if (connect(clientSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Failed to connect to server\n";
            return false;
        }

        NetworkUtils::setSocketTimeout(clientSocket, TIMEOUT_SECONDS);
        return true;
    }

    bool receiveFile(const std::string& authCode, const std::string& password, const std::string& saveDir) {
        encryptionKey = CryptoUtils::generateKey(password);
        saveDirectory = saveDir;

        if (!fs::exists(saveDirectory)) {
            if (!fs::create_directories(saveDirectory)) {
                std::cerr << "Failed to create save directory: " << saveDirectory << std::endl;
                return false;
            }
        }

        // Send auth code
        Message authRequest;
        authRequest.type = MessageType::AUTH_REQUEST;
        authRequest.length = static_cast<uint32_t>(authCode.length());
        authRequest.data.assign(authCode.begin(), authCode.end());

        if (!NetworkUtils::sendMessage(clientSocket, authRequest)) {
            std::cerr << "Failed to send auth request\n";
            return false;
        }

        // Receive auth response
        Message authResponse;
        if (!NetworkUtils::receiveMessage(clientSocket, authResponse) || 
            authResponse.type != MessageType::AUTH_RESPONSE) {
            std::cerr << "Failed to receive auth response\n";
            return false;
        }

        if (authResponse.data[0] != static_cast<uint8_t>(ErrorCode::SUCCESS)) {
            std::cerr << "Authentication failed\n";
            return false;
        }

        std::cout << "Authentication successful!" << std::endl;

        // Receive file info
        Message fileInfoMsg;
        if (!NetworkUtils::receiveMessage(clientSocket, fileInfoMsg) || 
            fileInfoMsg.type != MessageType::FILE_INFO) {
            std::cerr << "Failed to receive file info\n";
            return false;
        }

        FileInfo fileInfo;
        if (!parseFileInfo(fileInfoMsg.data, fileInfo)) {
            std::cerr << "Failed to parse file info\n";
            return false;
        }

        // Receive file data
        return receiveFileData(fileInfo);
    }

private:
    bool parseFileInfo(const std::vector<uint8_t>& data, FileInfo& fileInfo) {
        // Find the IV (last 16 bytes)
        if (data.size() < 16) return false;
        
        fileInfo.iv.assign(data.end() - 16, data.end());
        
        // Parse the rest
        std::string infoStr(data.begin(), data.end() - 16);
        std::istringstream iss(infoStr);
        std::string token;
        
        if (!std::getline(iss, token, '|')) return false;
        fileInfo.filename = token;
        
        if (!std::getline(iss, token, '|')) return false;
        fileInfo.size = std::stoull(token);
        
        if (!std::getline(iss, token, '|')) return false;
        fileInfo.checksum = token;
        
        return true;
    }

    bool receiveFileData(const FileInfo& fileInfo) {
        std::string filepath = saveDirectory + "\\" + fileInfo.filename;
        std::ofstream file(filepath, std::ios::binary);
        if (!file) {
            std::cerr << "Failed to create output file: " << filepath << std::endl;
            return false;
        }

        uint64_t totalReceived = 0;
        std::cout << "Receiving file: " << fileInfo.filename << " (" << fileInfo.size << " bytes)" << std::endl;

        while (totalReceived < fileInfo.size) {
            Message dataMsg;
            if (!NetworkUtils::receiveMessage(clientSocket, dataMsg)) {
                std::cerr << "Failed to receive data chunk\n";
                return false;
            }

            if (dataMsg.type == MessageType::FILE_COMPLETE) {
                break;
            }

            if (dataMsg.type != MessageType::FILE_DATA) {
                std::cerr << "Unexpected message type\n";
                return false;
            }

            // Extract chunk counter and encrypted data
            if (dataMsg.data.size() < 8) {
                std::cerr << "Invalid chunk data size\n";
                return false;
            }
            
            uint64_t chunkCounter = *reinterpret_cast<uint64_t*>(dataMsg.data.data());
            std::vector<uint8_t> encryptedChunk(dataMsg.data.begin() + 8, dataMsg.data.end());

            // Generate the same IV used for encryption
            auto chunkIV = CryptoUtils::generateChunkIV(fileInfo.iv, chunkCounter);

            // Decrypt chunk
            auto decryptedChunk = CryptoUtils::decryptData(encryptedChunk, encryptionKey, chunkIV);
            if (decryptedChunk.empty()) {
                std::cerr << "Decryption failed for chunk " << chunkCounter << std::endl;
                return false;
            }

            // Write to file
            file.write(reinterpret_cast<char*>(decryptedChunk.data()), decryptedChunk.size());
            totalReceived += decryptedChunk.size();

            // Progress indicator
            int progress = (int)((totalReceived * 100) / fileInfo.size);
            std::cout << "\rProgress: " << progress << "% (" << totalReceived << "/" << fileInfo.size << " bytes)" << std::flush;
        }

        std::cout << std::endl;
        file.close();

        // Verify checksum
        std::cout << "Verifying file integrity..." << std::endl;
        std::string receivedChecksum = CryptoUtils::calculateFileChecksum(filepath);
        
        if (receivedChecksum == fileInfo.checksum) {
            std::cout << "File transfer completed successfully!" << std::endl;
            std::cout << "File saved to: " << filepath << std::endl;
            return true;
        } else {
            std::cerr << "Checksum mismatch! File may be corrupted." << std::endl;
            fs::remove(filepath);
            return false;
        }
    }
};

void printUsage() {
    std::cout << "Secure File Transfer - Windows Version\n";
    std::cout << "Usage:\n";
    std::cout << "  Sender: program.exe send <filepath> [port]\n";
    std::cout << "  Receiver: program.exe receive <server_ip> <auth_code> <save_directory> [port]\n";
    std::cout << "\nExamples:\n";
    std::cout << "  program.exe send \"C:\\file.txt\"\n";
    std::cout << "  program.exe receive 192.168.1.100 123456 \"C:\\Downloads\"\n";
}

std::string getPassword() {
    std::cout << "Enter encryption password: ";
    std::string password;
    char ch;
    while ((ch = _getch()) != '\r') {
        if (ch == '\b') {
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else {
            password += ch;
            std::cout << '*';
        }
    }
    std::cout << std::endl;
    return password;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage();
        return 1;
    }

    if (!NetworkUtils::initializeWinsock()) {
        std::cerr << "Failed to initialize Winsock\n";
        return 1;
    }

    std::string mode = argv[1];
    int result = 0;

    try {
        if (mode == "send") {
            if (argc < 3) {
                printUsage();
                return 1;
            }

            std::string filepath = argv[2];
            int port = (argc > 3) ? std::stoi(argv[3]) : DEFAULT_PORT;

            FileTransferSender sender;
            if (!sender.startServer(port)) {
                std::cerr << "Failed to start server\n";
                return 1;
            }

            std::string password = getPassword();
            if (!sender.sendFile(filepath, password)) {
                std::cerr << "File transfer failed\n";
                result = 1;
            }

        } else if (mode == "receive") {
            if (argc < 5) {
                printUsage();
                return 1;
            }

            std::string serverIP = argv[2];
            std::string authCode = argv[3];
            std::string saveDirectory = argv[4];
            int port = (argc > 5) ? std::stoi(argv[5]) : DEFAULT_PORT;

            FileTransferReceiver receiver;
            if (!receiver.connectToSender(serverIP, port)) {
                std::cerr << "Failed to connect to sender\n";
                return 1;
            }

            std::string password = getPassword();
            if (!receiver.receiveFile(authCode, password, saveDirectory)) {
                std::cerr << "File transfer failed\n";
                result = 1;
            }

        } else {
            printUsage();
            result = 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        result = 1;
    }

    NetworkUtils::cleanupWinsock();
    return result;
}