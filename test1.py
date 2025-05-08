import sys 
sys.path.append("C:/Users/yuvraj/AppData/Local/Programs/Python/Python310/Lib/site-packages") 
import pyperclip

import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string
import re
import hashlib
import requests

# Global Theme Variable
dark_mode = True  # Default to Dark Mode

# Function to toggle between dark and light mode
def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode  # Switch mode
    
    bg_color = "#2e2e2e" if dark_mode else "white"
    text_color = "white" if dark_mode else "black"
    button_bg = "#444" if dark_mode else "#ddd"

    root.configure(bg=bg_color)
    style.configure("TLabel", foreground=text_color, background=bg_color)
    style.configure("TButton", background=button_bg)
    toggle_button.config(text="☀️ Light Mode" if dark_mode else "🌙 Dark Mode")

# Function to check if password has been breached
def check_breached_password():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Warning", "Enter a password to check.")
        return

    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    
    if response.status_code == 200:
        hashes = response.text.splitlines()
        breached = any(suffix in h.split(':')[0] for h in hashes)

        if breached:
            messagebox.showerror("Security Alert 🚨", "This password has been breached! Use a different one.")
        else:
            messagebox.showinfo("Safe ✅", "This password has NOT been found in breaches.")
    else:
        messagebox.showwarning("Error", "Could not check breached passwords. Try again later.")

# Function to generate a strong password
def generate_password():
    length = int(length_var.get())
    if length < 8:
        messagebox.showwarning("Error", "Password length must be at least 8!")
        return

    use_symbols = symbols_var.get()
    use_numbers = numbers_var.get()

    password_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase)
    ]

    if use_numbers:
        password_chars.append(secrets.choice(string.digits))

    if use_symbols:
        password_chars.append(secrets.choice(string.punctuation))

    characters = string.ascii_letters
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    password_chars.extend(secrets.choice(characters) for _ in range(length - len(password_chars)))
    secrets.SystemRandom().shuffle(password_chars)

    password = ''.join(password_chars)
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)

    analyze_password()

# Function to analyze password strength dynamically
def analyze_password(event=None):
    password = password_entry.get()
    strength = {
        "length": len(password) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "numbers": bool(re.search(r'\d', password)),
        "special_chars": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
    }

    score = sum(strength.values())
    strength_bar["value"] = score * 20  

    if score == 5:
        strength_label.config(text="Strength: Strong ✅", foreground="green")
    elif score >= 3:
        strength_label.config(text="Strength: Moderate ⚠️", foreground="orange")
    else:
        strength_label.config(text="Strength: Weak ❌", foreground="red")

# Function to toggle password visibility
def toggle_password_visibility():
    if password_entry.cget("show") == "":
        password_entry.config(show="*")
        show_button.config(text="👁 Show")
    else:
        password_entry.config(show="")
        show_button.config(text="🙈 Hide")

# Function to copy password to clipboard
def copy_to_clipboard():
    password = password_entry.get()
    if password:
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

# Create the main application window
root = tk.Tk()
root.title("Secure Password Tool")
root.configure(bg="#2e2e2e")

style = ttk.Style()
style.configure("TButton", padding=6, relief="flat", background="#444")

# UI Elements
ttk.Label(root, text="Enter or Generate Password:", foreground="white", background="#2e2e2e").grid(row=0, column=0, padx=5, pady=5)
password_entry = ttk.Entry(root, width=30, show="*")
password_entry.grid(row=0, column=1, padx=5, pady=5)
password_entry.bind("<KeyRelease>", analyze_password)

show_button = ttk.Button(root, text="👁 Show", command=toggle_password_visibility)
show_button.grid(row=0, column=2, padx=5)

strength_label = ttk.Label(root, text="Strength: ", foreground="white", background="#2e2e2e")
strength_label.grid(row=1, column=1, padx=5, pady=5)

strength_bar = ttk.Progressbar(root, length=200, mode='determinate', maximum=100)
strength_bar.grid(row=2, column=1, padx=5, pady=5)

generate_button = ttk.Button(root, text="Generate Password", command=generate_password)
generate_button.grid(row=3, column=0, columnspan=2, pady=5)

copy_button = ttk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=4, column=0, columnspan=2, pady=5)

# Breached Password Check Button
check_breach_button = ttk.Button(root, text="Check Breach 🔐", command=check_breached_password)
check_breach_button.grid(row=5, column=0, columnspan=2, pady=5)

# User Customization Options
ttk.Label(root, text="Password Length:", foreground="white", background="#2e2e2e").grid(row=6, column=0, padx=5, pady=5)
length_var = tk.StringVar(value="12")
length_entry = ttk.Entry(root, textvariable=length_var, width=5)
length_entry.grid(row=6, column=1, padx=5, pady=5)

symbols_var = tk.BooleanVar(value=True)
ttk.Checkbutton(root, text="Include Symbols", variable=symbols_var).grid(row=7, column=0, padx=5, pady=5)

numbers_var = tk.BooleanVar(value=True)
ttk.Checkbutton(root, text="Include Numbers", variable=numbers_var).grid(row=7, column=1, padx=5, pady=5)

toggle_button = ttk.Button(root, text="☀️ Light Mode", command=toggle_theme)
toggle_button.grid(row=8, column=0, columnspan=2, pady=5)

# Developer Credit Label
ttk.Label(root, text="Made by Yuvraj Gupta", foreground="gray", background="#2e2e2e", font=("Arial", 10, "italic")).grid(row=9, column=0, columnspan=2, pady=10)


# Run the application
root.mainloop()
