#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>

std::string ComputeSha256Hash(const std::string& rawData) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create OpenSSL context!" << std::endl;
        return "";
    }

    const EVP_MD* md = EVP_sha256();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, rawData.c_str(), rawData.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
        std::cerr << "Failed to compute SHA-256 hash!" << std::endl;
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main() {
    std::string hashToCrack;
    std::string dictionaryPath = "manypasswords.dict";
    std::string sha256HashPath = "hashesSha256.txt";
    std::string md5HashPath = "hashesMd5.txt";
    std::string userInp;
    bool sha256 = false;


    while (true) {
        if (hashToCrack.empty()) {
            std::cout << "Enter 1 for SHA256 and 2 for MD5" << std::endl;
            std::getline(std::cin, userInp);
            if(userInp == "1"){
                sha256 = true;
                std::cout << " Okay, make sure to enter a SHA256 hash." << std::endl;
            }else if(userInp == "2"){
                sha256 = false;
                std::cout << " Okay, make sure to enter a MD5 hash." << std::endl;
            }else{
                std::cout << " Please input either 1 or 2" << std::endl;
                continue;
            }

            std::cout << "Please enter a hash you'd like to try!" << std::endl;
            std::getline(std::cin, hashToCrack);
            
            std::ifstream dictionary(dictionaryPath);
            std::ifstream hashMd5(md5HashPath);
            std::ifstream hashSha256(sha256HashPath);
            
            if (!dictionary || !hashMd5 || !hashSha256) {
                std::cerr << "Failed to open dictionary or hash file!" << std::endl;
                return 1;
            }
            std::ifstream &hash = (sha256) ? hashSha256 : hashMd5;
            std::string line;
            while (std::getline(hash, line)) {
                size_t delimiterPos = line.find(":");

                if (delimiterPos != std::string::npos) {
                    std::string password = line.substr(0, delimiterPos);
                    std::string hashedPw = line.substr(delimiterPos + 1);

                    if (hashedPw == hashToCrack) {
                        std::cout << "Password found: " << password << std::endl;
                        std::cout << "Try another hash!" << std::endl;
                        hashToCrack.clear();
                        break;
                    }
                }
            }
        }
    }
    return 0;
}
