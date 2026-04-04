from zkp_protocol import Server, Client
from getpass import getpass
import sys


def print_header():
    print("\n" + "=" * 60)
    print("    Passwordless zkSNARK Authentication System")
    print("=" * 60)


def print_menu():
    print("\nWelcome! Choose an option:")
    print("1. Register New User")
    print("2. Login")
    print("3. Exit")
    print("-" * 60)


def register_user(server, client):
    print("\n" + "-" * 60)
    print("REGISTRATION")
    print("-" * 60)
    
    hr_id = input("\nEnter your HR_ID/Username: ").strip()
    if not hr_id:
        print("[ERROR] HR_ID cannot be empty!")
        return
    
    password = getpass("Enter your password: ")
    if not password:
        print("[ERROR] Password cannot be empty!")
        return
    
    password_confirm = getpass("Confirm your password: ")
    if password != password_confirm:
        print("[ERROR] Passwords do not match!")
        return
    
    print("\nProcessing registration...")
    print("[*] Requesting field element g0 from server...")
    g0 = server.get_random_g0()
    
    print("[*] Computing zkSNARK commitment...")
    registration_data = client.register(hr_id, password, g0)
    
    success, message = server.register_user(
        registration_data['hr_id'],
        registration_data['Y'],
        registration_data['g0']
    )
    
    if success:
        print("\n[SUCCESS] Registration successful!")
        print(f"User '{hr_id}' has been registered.")
        print("Note: A zkSNARK commitment was stored instead of your password.")
    else:
        print(f"\n[FAILED] Registration failed: {message}")


def login_user(server, client):
    print("\n" + "-" * 60)
    print("LOGIN")
    print("-" * 60)
    
    hr_id = input("\nEnter your HR_ID/Username: ").strip()
    if not hr_id:
        print("[ERROR] HR_ID cannot be empty!")
        return
    
    password = getpass("Enter your password: ")
    if not password:
        print("[ERROR] Password cannot be empty!")
        return
    
    # Retrieve g0 for this user from server
    if hr_id not in server.users:
        print(f"[ERROR] User '{hr_id}' not found. Please register first.")
        return
    
    client.g0 = server.users[hr_id]['g0']
    client.commitment = server.users[hr_id]['Y']
    
    print("\nProcessing authentication...")
    print("[*] Generating zkSNARK proof (requires circom/snarkjs artifacts)...")
    try:
        login_payload = client.login(hr_id, password)
    except RuntimeError as exc:
        print(f"[ERROR] Unable to generate zkSNARK proof: {exc}")
        print("Please ensure you've run 'pwsh scripts/setup_snark.ps1' and installed snarkjs.")
        return
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return
    
    print("[*] Sending proof to server for verification...")
    auth_success, auth_message = server.authenticate_user(
        login_payload['hr_id'],
        login_payload['proof'],
        login_payload['public_signals']
    )
    
    if auth_success:
        print("\n[SUCCESS] Authentication verified!")
        print(f"Welcome back, {hr_id}!")
        print("Your identity was proven without revealing your password.")
    else:
        print(f"\n[FAILED] Authentication failed: {auth_message}")
        print("Please check your username and password.")


def main():
    print_header()
    
    server = Server()
    client = Client()
    
    print("\n[INFO] Server initialized (zkSNARK verification key expected in 'keys').")
    print("[INFO] Run 'pwsh scripts/setup_snark.ps1' before attempting authentication.")
    
    while True:
        print_menu()
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            register_user(server, client)
            input("\nPress Enter to continue...")
        elif choice == "2":
            login_user(server, client)
            input("\nPress Enter to continue...")
        elif choice == "3":
            print("\nThank you for using the Passwordless zkSNARK Authentication System!")
            print("Goodbye!")
            sys.exit(0)
        else:
            print("\n[ERROR] Invalid choice! Please enter 1, 2, or 3.")
            input("Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\nProgram interrupted by user.")
        print("Goodbye!")
        sys.exit(0)

