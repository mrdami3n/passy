-----

# Passy - The Secure Password Manager 🔐

 

A secure, local-first desktop password manager built with Python and PyQt5. Passy helps you manage your sensitive information—passwords, secure notes, and crypto wallet details—with robust encryption and modern security features.

Created by **Dami3n Thron** of **Thorn Industries**.

-----

## ✨ Key Features

  * **Secure Local Storage**: All your data is stored locally in an encrypted `vault.db` file. Nothing is ever sent to the cloud.
  * **End-to-End Encryption**: Utilizes `Fernet` (AES-128 in CBC mode) for symmetric encryption of all your vault data. Your master password is the only key.
  * **Strong Master Password Hashing**: Uses `bcrypt` to securely hash your master password, protecting it against brute-force attacks.
  * **Two-Factor Authentication (2FA)**: Secure your account with TOTP-based 2FA. Simply scan a QR code with your favorite authenticator app (Google Authenticator, Authy, etc.).
  * **Recovery Codes**: Generate single-use recovery codes to ensure you never lose access to your account.
  * **Password Health Audit**: A comprehensive security dashboard that flags:
      * **Reused Passwords**: Identifies passwords used across multiple accounts.
      * **Weak Passwords**: Flags passwords that are easy to guess.
      * **Old Passwords**: Reminds you to update passwords older than 6 months.
      * **Pwned Passwords**: Checks your passwords against the 'Have I Been Pwned' database via a secure, anonymous API.
  * **Versatile Vault**: Store more than just passwords\!
      * **Secure Notes**: A dedicated space for any sensitive text.
      * **Crypto Wallet Manager**: Securely store wallet names, addresses, private keys, and recovery phrases.
  * **Advanced Security Tools**:
      * **Customizable Password Generator**: Create strong, unique passwords with options for length and character types.
      * **Automatic Logout**: The vault locks automatically after 5 minutes of inactivity.
      * **Clipboard Management**: Copied passwords are automatically cleared from the clipboard after 30 seconds.
  * **Data Portability**:
      * **Encrypted JSON Export/Import**: Securely back up and restore your entire vault.
      * **Unencrypted CSV Export**: For migrating passwords to other services (use with caution\!).
  * **Modern UI**: A clean and intuitive user interface built with PyQt5, featuring both **Dark and Light themes**.

-----

## 🚀 Getting Started

Follow these instructions to get a copy of the project up and running on your local machine.

### Prerequisites

You need to have Python 3 installed on your system. You can download it from [python.org](https://www.python.org/).

### Installation & Setup

1.  **Clone the repository:**

    ```sh
    git clone https://github.com/your-username/your-repository-name.git
    cd your-repository-name
    ```

2.  **Create a virtual environment (recommended):**

    ```sh
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install the required packages:**
    A `requirements.txt` file is needed to list all dependencies. Create this file in your project directory with the following content:

    **`requirements.txt`**

    ```
    PyQt5
    cryptography
    bcrypt
    pyotp
    qrcode[pil]
    requests
    ```

    Then, run the installation command:

    ```sh
    pip install -r requirements.txt
    ```

### How to Run the Application

Once the setup is complete, you can run the application with a single command:

```sh
python your_main_file_name.py
```

*(Replace `your_main_file_name.py` with the actual name of your Python file).*

A window will open, prompting you to either create a new account or log in.

-----

## 📖 How to Use

1.  **Create an Account**: On the first launch, use the "Create Account" button. Choose a strong, memorable Master Password.
2.  **Set Up 2FA**: After creating your account, you'll be prompted to set up 2FA.
      * Scan the generated `qrcode.png` with your authenticator app.
      * **Crucially, save the provided recovery codes in a safe, offline location.**
3.  **Log In**: Use your username, master password, and a 6-digit 2FA code to unlock your vault.
4.  **Manage Your Data**: Use the tabs to add, edit, view, and delete your passwords, notes, and crypto wallet information.
5.  **Audit Your Security**: Regularly visit the "Password Audit" tab and run a health check to identify and fix security weaknesses in your passwords.
6.  **Back Up Your Vault**: Use the `Options -> Export Vault...` menu to create an encrypted JSON backup of your data.

-----

## 🛡️ Security Considerations

  * **Your Master Password is Everything**: Your master password is never stored directly. It is the key to decrypting your entire vault. **If you forget it, your data is permanently inaccessible.** There is no recovery mechanism for a lost master password.
  * **Local-Only Database**: The `vault.db` file contains all your encrypted information. It is stored on your local machine only. Keep this file safe.
  * **CSV Export Warning**: Exporting to CSV creates an unencrypted, plain-text file. Anyone with access to this file can read all your passwords. Use this feature with extreme caution and delete the file securely after use.
  * **Crypto Wallet Risk**: Storing digital asset recovery phrases or private keys in any digital format is inherently risky. The recommended best practice is to store them offline (e.g., on paper or a hardware wallet). This feature is provided for convenience but must be used with a full understanding of the risks involved.

-----

## 📜 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
