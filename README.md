# NovalEnc

A modern encryption and decryption tool with a user-friendly interface.

## 🚀 Features

- **Strong Encryption**: Secure file and text encryption using industry-standard algorithms
- **User-Friendly Interface**: Simple and intuitive GUI for easy operation
- **Cross-Platform**: Works on Windows systems
- **Fast Performance**: Quick encryption and decryption processes
- **Standalone Executable**: No installation required - run directly from the executable

## 📦 Installation

### Option 1: Use Pre-built Executable (Recommended)

1. Download the latest release from the [Releases](https://github.com/ZiadTamer77/NovalEnc/releases) page
2. Navigate to the `dist` folder
3. Run `NovalEnc.exe`

No installation or dependencies required!

### Option 2: Run from Source

**Prerequisites:**
- Python 3.8 or higher
- pip (Python package manager)

**Steps:**

1. Clone the repository:
```bash
git clone https://github.com/ZiadTamer77/NovalEnc.git
cd NovalEnc
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python main.py
```

## 🎯 Usage

1. Launch the application by running `NovalEnc.exe` from the `dist` folder
2. Choose whether to encrypt or decrypt
3. Select your input file or enter text directly
4. Enter your encryption key/password
5. Click the process button to complete the operation
6. Save the output to your desired location

## 🔒 Security

- **Strong Encryption**: Uses robust encryption algorithms to protect your data
- **Password Protection**: Your files are secured with password-based encryption
- **No Data Collection**: All operations are performed locally on your machine
- **Open Source**: The code is publicly available for security audits

## 🛠️ Building from Source

To build the executable yourself:

1. Install required dependencies:
```bash
pip install -r requirements.txt
pip install pyinstaller
```

2. Build the executable:
```bash
pyinstaller --onefile --windowed main.py
```

3. The executable will be created in the `dist` folder

## 📋 Requirements

- **For Executable**: Windows 7 or higher
- **For Source**: Python 3.8+ with required packages (see `requirements.txt`)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Ziad Tamer**
- GitHub: [@ZiadTamer77](https://github.com/ZiadTamer77)

## ⚠️ Disclaimer

This tool is provided for legitimate encryption purposes only. Users are responsible for complying with all applicable laws and regulations. Always keep backups of your encryption keys and important files.

## 🐛 Bug Reports & Feature Requests

If you encounter any bugs or have feature requests, please [open an issue](https://github.com/ZiadTamer77/NovalEnc/issues) on GitHub.

## 📊 Project Status

Active Development - Contributions and feedback welcome!

---

**Note**: Remember your encryption passwords! Lost passwords cannot be recovered, and encrypted data will be permanently inaccessible.
