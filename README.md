# 🧩 Stego Tool (Safe LSB Steganography)

A secure, lightweight Python tool for embedding and extracting **arbitrary files** inside **PNG/BMP images** using **Least Significant Bit (LSB) steganography**.  
Includes both **CLI** and **GUI** interfaces, with optional **Fernet encryption** for added security.

---

## ⚙️ Features

- 🔒 **Safe Steganography** — No auto-execution, no persistence, just pure data embedding/extraction.  
- 🧠 **Fernet Encryption** — Optional symmetric encryption for payload confidentiality.  
- 🖼️ **Image Support** — Works with PNG and BMP formats.  
- 🧰 **Two Interfaces**:
  - **Command-Line Interface (CLI)** for automation/scripting.
  - **Graphical User Interface (GUI)** built with Tkinter for ease of use.

---

## 🧱 Requirements

- **Python** 3.8 or higher  
- **Pip** and **virtualenv** (recommended)

---

## 🪜 Installation and Setup

### 1️⃣ Clone or Download

```bash
git clone https://github.com/cyber-raavan/Project_Internelevatelab
cd ./Project_Internelevatelab
```

Or simply place the file `stego_tool.py` in your desired directory.

---

### 2️⃣ Create and Activate Virtual Environment

```bash
python -m venv .venv
```

#### On Windows:
```bash
.venv\Scripts\activate
```

#### On Linux/macOS:
```bash
source .venv/bin/activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install --upgrade pip
pip install pillow cryptography
```

---

## 🧮 Command-Line Usage (CLI)

### 🧾 Show Help
```bash
python stego_tool.py --help
```

---

### 🔑 Generate a Fernet Key
This key is optional but required if you want encryption/decryption.

```bash
python stego_tool.py genkey
```

Output example:
```
DvA6u2rq9pCJzY6zIY6wPUyC27dB3Ncc1sJzYtVYz4Y=
```

---

### 📥 Embed (Hide a File)
```bash
python stego_tool.py embed --cover cover.png --infile secret.txt --out stego.png
```

With encryption:
```bash
python stego_tool.py embed --cover cover.png --infile secret.txt --out stego.png --key DvA6u2rq9pCJzY6zIY6wPUyC27dB3Ncc1sJzYtVYz4Y=
```

---

### 📤 Extract (Retrieve Hidden File)
```bash
python stego_tool.py extract --stego stego.png --outdir ./output
```

With decryption:
```bash
python stego_tool.py extract --stego stego.png --outdir ./output --key DvA6u2rq9pCJzY6zIY6wPUyC27dB3Ncc1sJzYtVYz4Y=
```

---

## 🪟 Graphical Interface (GUI)

Launch the GUI with:
```bash
python stego_tool.py gui
```

### 🖥️ GUI Features

| Function | Description |
|-----------|--------------|
| **Choose cover image** | Select a PNG/BMP image to embed data into |
| **Choose file to hide** | Select any file you wish to conceal |
| **Generate Key** | Create a new Fernet encryption key |
| **Embed** | Hide the file into the cover image |
| **Choose stego image** | Select a stego image for extraction |
| **Extract** | Retrieve the hidden file into the chosen output directory |

> 💡 If encryption is used, the same key must be provided during extraction.

---

## 📂 Output

- Embedded images are always saved as `.png`
- Extracted files retain their **original filename** and are saved to the specified output directory.

---

## 🧩 Technical Overview

| Component | Description |
|------------|-------------|
| **LSB Steganography** | Uses least significant bits of RGB channels to store data |
| **Header Structure** | Includes a magic signature (`STEGOV1`), payload size, and filename metadata |
| **Encryption** | Optional AES-128 (Fernet) encryption for payload data |
| **Safety** | No automatic execution, no persistence, no hidden scripts |

---

## 🧠 Example Workflow

```bash
# Step 1: Generate key
python stego_tool.py genkey
# -> Save key safely

# Step 2: Embed secret file
python stego_tool.py embed --cover cover.png --infile secret.txt --out stego.png --key <your_key>

# Step 3: Extract hidden file
python stego_tool.py extract --stego stego.png --outdir ./extracted --key <your_key>
```

---

## 🧰 Troubleshooting

| Issue | Possible Cause / Fix |
|--------|----------------------|
| `Payload too big` | Cover image too small. Use a higher resolution PNG. |
| `Magic header not found` | File not created with this tool or corrupted. |
| `Decryption failed` | Wrong key or non-encrypted data. |
| GUI doesn’t start | Missing `tkinter` — install via `sudo apt install python3-tk` (Linux). |

---

## 🧑‍💻 Author
Developed by **Kush Thaker**  
Secure Steganography Research & Cybersecurity Applications, 2025

---

## 📜 License
MIT License – Free to use and modify for research, academic, and personal projects.
