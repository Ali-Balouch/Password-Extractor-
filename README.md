	#############################################################################################################################################
	#						     
	# 		@#* Password Extractor Tool *#@ 	     
	#						     
	#############################################################################################################################################
	#
	#	Password Extractor Tool is a Windows-based tool designed to help users extract specific types of information from Google Chrome and Microsoft Edge
 	#	browsers , SAM file and scan temporary folders for sensitive information. It leverages SQLite database queries to extract saved passwords from Chrome and Edge
 	#	and scans system directories for sensitive information related to keywords such as username, email, and passwords. Results can be exported to a CSV 
	#	file and saved on the Document by defult.
	#
	#############################################################################################################################################
	#  
	#   => Table of Contents
	#	
	#	* Features
	#	* Requirements
	#	* Installation
	#	* Libraries Overview
	#	* Functionalities
	#		1. Chrome Password Extractor
	#		2. Edge Password Extractor
	#		3. Temporary Folder Scanner
	#		4. SAM File Extrator
	#		5. Save Results to CSV
	#		6. Search Result
	#		7. Check Specific Profile of Chrome/Edge
	#		8. About Page
	#		9. Sort Data
	#		10. Main Page
	#	* Usage
	#
	############################################################################################################################################
	#
	#  => Features
	#
	#	1. Extracts saved passwords from Google Chrome and Microsoft Edge.
	#	2. Retrieves passwords saved by the browsers using SQLite database access and decryption techniques.
	#	3. Find SAM file, create its backup file on the system.
	#	4. Scans system temporary folders (e.g., Downloads, Desktop, Documents) for sensitive information using specific keywords.
	#	5. Saves scan results in CSV format on the Documents for further analysis or record-keeping.
	#	6. Includes an About page with version details and developer information.
	#	7. The central dashboard for managing and navigating the entire application’s features.
	#	8. Allows users to search for specific keywords or file types within the scan results or system files.
	#	9. If multiple user profiles are detected (e.g., in Chrome or Edge), the user can select a specific profile from a dropdown list to extract data from.
	#	10. Buttons to control actions such as initiating a scan, clearing results, returning to the main page, and saving results in CSV format.
	#       11. Allows users to click on table column headers (e.g., for passwords, file names) to sort the data in ascending order.
	#       12. Alerts or notifications that inform the user of completed tasks, errors, or warnings during operations (e.g., “Scan Completed,” “No Results Found”).
	#       13. Displays the progress of ongoing tasks, such as scanning, so the user is aware of the operation’s status.
 	#
	#############################################################################################################################################
	#
	#
	#  => Requirements
	#
	#	* Operating System: Windows
	#	* Permissions: Run the program as an administrator
	#	* Applications: Requires Google Chrome and Microsoft Edge installed on the system.
	#	* Installation: Python installed on the system and any IDE to run .py file.
	#
	#############################################################################################################################################
	#
	#
	#  =>Installation
	#
	#	Clone the repository or download the project files, and then install the required libraries using the following commands:
	#
	#	> pip install pycryptodome # For AES decryption 
	#	> pip install pypiwin32 # For Windows encryption
	#	> pip install pycryptodomex # For cryptography functions
	#
	#
	#############################################################################################################################################
	#
	#
	#  => Libraries Overview
	#
	#	1. os
	#	* Purpose: Manages system and directory operations.
	#	* Usage: No installation required; comes pre-installed with Python.	
	#
	#	2. sqlite3
	#	* Purpose: Interfaces with the SQLite database where Chrome and Edge passwords are stored.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#	3. base64
	#	* Purpose: Handles encoding and decoding of extracted data.
	#	* Usage: No installation required; comes pre-installed with Python.
	#	
	#	4. json
	#	* Purpose: Parses JSON data.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#	5. shutil
	#	* Purpose: Manages file and directory operations, such as moving files.
	#	* Usage: No installation required; comes pre-installed with Python.	
	#
	#	6. tempfile
	#	* Purpose: Creates temporary files and directories.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#	7. tkinter
	#	* Purpose: Creates a graphical user interface (GUI) for user interaction.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#	8. Crypto.Cipher.AES (from pycryptodome)
	#	* Purpose: Decrypts data using AES encryption.
	#	* Command: pip install pycryptodome
	#
	#	9. win32crypt (from pypiwin32)
	#	* Purpose: Decrypts saved passwords in Chrome and Edge.
	#	* Command: pip install pypiwin32
	#
	#	10. datetime
	#	* Purpose: Handles date and time operations for timestamps.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#	11. csv
	#	* Purpose: Writes results to CSV files.
	#	* Usage: No installation required; comes pre-installed with Python.
	#	
	#	12. threading
	#	* Purpose: Provides functionality for running multiple threads concurrently, useful for performing background tasks 
	#	  without freezing the main application.
	#	* Command: No installation required; comes pre-installed with Python.
	#	
	#	13. Toplevel (from tkinter)
	#	* Purpose: Creates new windows within a tkinter GUI application, allowing for multi-window interfaces.
	#	* Usage: No installation required; comes pre-installed with Python.
	#	
	#	14. sys
	#	* Purpose: Provides access to system-specific parameters and functions.
	#	* Usage: No installation required; comes pre-installed with Python.
	#	
	#	15. ctypes
	#	* Purpose: Interacts with C libraries and Windows system functions.
	#	* Usage: No installation required; comes pre-installed with Python.
	#	
	#	16.Label, Frame, Entry, Button, StringVar, OptionMenu, scrolledtext, messagebox (from tkinter)
	#	* Purpose: Provides various GUI components like text boxes, labels, and buttons.
	#	* Usage: No installation required; comes pre-installed with Python.
	#	
	#	17. ttk
	#	* Purpose: Enhances tkinter with themed widgets and styles.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#	18. filedialog (from tkinter)
	#	* Purpose: Opens file and directory dialogs for user input.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#	19. subprocess
	#	* Purpose: Executes external processes and shell commands.
	#	* Usage: No installation required; comes pre-installed with Python.
	#
	#
	#############################################################################################################################################
	#
	#
	#	1. Chrome Password Extractor
	#	Extracts saved passwords from Google Chrome's Login Data SQLite database. This database file is decrypted using the AES and win32crypt
	#	libraries to obtain readable credentials.
	#
	#	2. Edge Password Extractor
	#	Similar to Chrome, Edge saves its credentials in an SQLite database, and this tool can decrypt the Edge database to retrieve saved usernames and passwords.
	#
	#	3. Temporary Folder Scanner
	#	Scans system folders, such as Desktop, Downloads, Documents, StickyNotes, Clipboard and temp files, for files that contain keywords like username, email, password, and credential.
	#	It searches within text-based files, identifying sensitive information and displaying the file path and matching content.
	#	
	#	4. SAM File Scanner
	#	Scans the Security Account Manager (SAM) file, which stores hashed user credentials in Windows systems.
	#	It extracts hashed passwords, user account information, and other sensitive data for analysis, enabling identification of potential vulnerabilities or unauthorized access.
	#	The scanner processes the SAM file securely, displaying account details and any retrieved hashes for further investigation.
	#
	#	5. Save Results to CSV
	#	Results from password extraction and temporary folder scanning can be saved in a CSV file by default to the Documents folder, making it easy for users to 
	#	analyze extracted data.
	#	
	#	6. Hax Viewer
	#	Show Hax values of complete output in the form of hex viewer. User can search specific value from it by searching in the search box.
	#
	#	7. About Page
	#	Displays information about the tool, including its version, purpose, instructions, and developer credits.
	#
	#	8. Main Page
	#	The main page serves as the central control, containing buttons to navigate to each function:
	#
	#		1. Temp Data Scan: Starts a scan of temporary folders.
	#		2. SAM Scan: Find and Extract SAM file
			3. Chrome Scan: Extracts and decrypts saved passwords from Chrome.
	#		4. Edge Scan: Extracts and decrypts saved passwords from Edge.
	#		5. About: Displays information about the tool.
	#		6. Exit: Exits the application.
	#
	#############################################################################################################################################
	#
	#  => Usage
	#
	#	1. Ensure you are Running the program as an Administrator.
	#	2. Open the application and select the desired function on the main page:
	#		* Temp Data Scan: Starts a scan of system temporary folders.
	#		* SAM Scan: Start scan of system, sometimes antivirus or firewall issues appears.
	#		* Chrome Scan: Initiates Chrome password extraction.
	#		* Edge Scan: Initiates Edge password extraction.
	#		* About: Displays program details.
	#	3. View results on the interface or save them to a CSV file.
	#	4. view Hax Table of each function.
	#
	#############################################################################################################################################