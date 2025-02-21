# 🌐 WebListener - HTTP/HTTPS Traffic Inspector

[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=102)](https://github.com/hr0g/WebListener/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Windows Build](https://img.shields.io/badge/Platform-Windows-0078d7.svg)](https://www.microsoft.com/windows)

A powerful C++ based proxy server for intercepting and analyzing HTTP/HTTPS traffic on Windows systems.

![Proxy Architecture](https://github.com/user-attachments/assets/f485ab83-5dcd-4462-84e3-de76283bff80)

## 🚀 Features

- **Dual Protocol Support**
  - Full HTTP/HTTPS traffic interception
  - SSL/TLS decryption capabilities
  - Transparent proxy configuration

- **Advanced Monitoring**
  - Real-time traffic inspection
  - Request/Response header analysis
  - Payload content decoding

- **Security Tools**
  - Custom CA certificate management
  - MITM (Man-in-the-Middle) detection prevention
  - Secure connection validation

## 🛠️ Setup Guide

### Prerequisites
- Windows 10/11 64-bit
- Visual Studio 2022
- vcpkg package manager

### Dependency Installation
```powershell
# Install vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.bat

# Install required libraries
./vcpkg install openssl:x64-windows zlib boost-iostreams boost-system boost-thread boost-beast
```

### Project Configuration
1. Add vcpkg paths to Visual Studio:
   ```
   Include Path: E:\vcpkg\installed\x64-windows\include
   Library Path: E:\vcpkg\installed\x64-windows\lib
   ```

2. Generate certificates:
```bash
# Root CA
openssl genrsa -out root-key.pem 4096
openssl req -x509 -new -nodes -key root-key.pem -sha384 -days 3650 \
  -out root-cert.pem \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=Security Lab/CN=Global Security Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "certificatePolicies=1.3.6.1.4.1.4146.1.20" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid:always"

# Server Certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## 🔧 Proxy Configuration

### Firefox Settings
1. Navigate to `about:preferences#general`
2. Scroll to **Network Settings**
3. Configure manual proxy:
   ```
   HTTP Proxy: 127.0.0.1:8080
   HTTPS Proxy: 127.0.0.1:8080    
   SOCK PROXY: 127.0.0.1:8080
   ```

![Firefox Proxy Settings](https://github.com/user-attachments/assets/4700ddb8-80e5-479e-a6ba-d2b5e407aab2)


## 🖥️ usage method

### Quick Start

1. Clone the repository and build the project

2. Run in the root directory of the project:

### Start using default port

https_proxy(port 8080).exe
https_server(port 8080).exe
https_requester(port 8080).exe


## 📊 Traffic Analysis
![HTTPS Inspection](https://github.com/user-attachments/assets/0ef8487e-fa41-4577-88e9-e36899cbe6a1)

## 📜 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing
We welcome contributions! Please read our [CONTRIBUTING](CONTRIBUTING.md) guide before submitting pull requests.

---

**Security Note**: Use this tool only on networks you own or have permission to monitor. Always respect privacy laws and regulations.
```
