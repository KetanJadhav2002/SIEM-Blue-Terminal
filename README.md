# SIEM-Blue-Terminal
This Windows tool used to monitor System Logs, Network Traffic, Processes etc. on localhost and it collects data only from local machine it stores logs before logout

Requirement is :

1. System-Level Prerequisites (Drivers)
These are mandatory because Python cannot talk to your hardware or restricted logs without them.
Npcap (for Network Sniffing):
Download here.
CRITICAL: During installation, you must check the box: "Install Npcap in WinPcap API-compatible Mode". If you skip this, the Network tab will not work.
Administrator Privileges:
You must run your Command Prompt (CMD), PowerShell, or VS Code as Administrator.
Reason: Windows prevents non-admin users from reading the Security Log (logins) and sniffing raw network packets.

2. Database Environment (XAMPP / MySQL)
The tool uses MySQL to manage the login session for the user Ketan.
Software: Install XAMPP or WAMP.
Configuration:
Start the MySQL module in the XAMPP Control Panel.
The database user Admin with password Admin@123 must have "Global Privileges" (Check All) in phpMyAdmin.
Action: You must run python init_db.py once before starting the app to create the SIEM_DB.

3. Python Environment
Python Version: Python 3.10, 3.11, or 3.12 (Recommended).
Required Python Modules:
Run this command in your Administrator CMD:
code
Cmd
python -m pip install flask waitress psutil scapy pymysql pywin32
flask: Handles the web routes.
waitress: Production server (prevents "Development Server" warnings).
psutil: Collects CPU, RAM, and Process data.
scapy: The engine for the Network Analyzer.
pymysql: Connects Python to your MySQL database.
pywin32: Allows access to Windows Event Logs (win32evtlog).

4. Project Directory Structure
For the .py script and the .exe to find the HTML/CSS files, your folder must look exactly like this:
code
Text
BlueTeam/
├── Database/         (Created automatically)
├── Logs/             (Created automatically)
├── NetPacket/         (Created automatically)
├── static/           (Folder for CSS/JS)
├── template/         (Note: Folder name is 'template', NOT 'templates')
│   ├── login.html
│   └── layout.html
├── app.py
└── init_db.py

5. Deployment Requirements (for .exe)
If you are converting the project to an .exe using PyInstaller, use this exact command to ensure all "hidden" Windows and MySQL modules are included:
code

Cmd
pyinstaller --noconfirm --onefile --console --uac-admin --add-data "template;template" --add-data "static;static" --hidden-import "pymysql" --hidden-import "win32evtlog" --hidden-import "win32api" --hidden-import "win32security" app.py
--uac-admin: This makes the .exe automatically ask for "Run as Administrator" permission when you double-click it.


Summary Checklist to Avoid Errors:
      XAMPP/MySQL is Running.
      Npcap is installed with WinPcap compatibility checked.
      Administrator CMD is being used.
      init_db.py was run successfully.

template folder (singular) contains layout.html and login.html.
If you follow these steps, the "SIEM-Blue is Hosted at: http://127.0.0.1:12345" message will appear, and all modules will function with 100% accuracy.
