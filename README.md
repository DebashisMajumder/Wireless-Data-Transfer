# 📂 Wireless File Share (Raspberry Pi Zero 2 W)

A lightweight **wireless file sharing web server** built using **Flask**, designed and tested on a **Raspberry Pi Zero 2 W**.  
It allows you to upload, download, and delete files over your **local Wi-Fi network** using any modern web browser — no USB cables, no extra apps.

---

## 🚀 Features

- 📡 Access from any device on the same Wi-Fi network
- 📤 Drag & drop file uploads
- 📊 Live upload progress bar
- 📥 Download files directly from browser
- 🗑 Delete files from web UI
- 📦 Real-time storage usage monitoring
- 🔄 Automatic refresh (no manual reload needed)
- 📷 QR code for instant phone access
- 🌗 Day / Night mode toggle
- 📱 Fully responsive (PC, tablet, mobile)
- ⚡ Optimized for **Raspberry Pi Zero 2 W**

---

## 🧠 Hardware Used

- **Raspberry Pi Zero 2 W**
- microSD card (8 GB or more recommended)
- Wi-Fi connection
- 5V power supply

---

## 🧰 Software Requirements

- Raspberry Pi OS (Lite or Desktop)
- Python **3.9+**
- Flask

---

## 📁 Project Structure

Wireless-File-Share/
│
├── app.py
├── templates/
│ └── index.html
├── uploads/
│ └── (uploaded files stored here)
├── README.md


---

## 🔧 Installation & Setup (Pi Zero 2 W)

### 1️⃣ Update your Raspberry Pi
```bash

sudo apt update && sudo apt upgrade -y

2️⃣ Install Python & pip (if not installed)
sudo apt install python3 python3-pip -y

3️⃣ Install Flask
pip3 install flask

▶️ Running the Server
1️⃣ Clone or copy the project
git clone https://github.com/yourusername/wireless-file-share.git
cd wireless-file-share


(Or manually copy files to your Pi.)

2️⃣ Create uploads directory
mkdir -p uploads

3️⃣ Run the server
python3 app.py


You should see:

Running on http://0.0.0.0:5000/

🌐 Accessing the Server
On the Raspberry Pi itself:
http://localhost:5000

From another device (phone / laptop):

Find the Pi’s IP address:

hostname -I


Open in browser:

http://<PI_IP_ADDRESS>:5000


📷 Or simply scan the QR code shown in the web interface.

🔄 Auto Refresh Behavior

File list updates automatically

Storage usage updates live

Upload progress updates in real time

No manual browser refresh required

📦 Upload Folder Location

Files are stored at:

/home/debashis/Project/WDT (Wireless Data Transfer)/uploads


You can change this path in app.py:

UPLOAD_FOLDER = '/your/custom/path/uploads'

🛡 Security Notes

Designed for local network use only

No authentication (intentional for simplicity)

Do NOT expose to the internet without protection

For public access, consider:

Password authentication

HTTPS (nginx + certbot)

Firewall rules

⚡ Performance Notes (Pi Zero 2 W)

Best suited for:

Small to medium file transfers

Local Wi-Fi usage

Avoid extremely large files (>5–10 GB)

2.4 GHz Wi-Fi recommended

🔁 Run on Boot (Optional)

To automatically start the server on boot:

crontab -e


Add:

@reboot python3 /home/pi/Wireless-File-Share/app.py &

🧪 Tested On

Raspberry Pi Zero 2 W

Raspberry Pi OS

Android browsers

iOS Safari

Desktop Chrome & Firefox

🧑‍💻 Built With

Python 🐍

Flask 🌶

HTML / CSS / JavaScript

QRCode.js

📜 License

MIT License — free to use, modify, and distribute.

❤️ Author

Built and tested on Raspberry Pi Zero 2 W
for fast, simple, cable-free local file sharing.
