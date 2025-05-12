print("Welcome to PyPass")
# Removed unnecessary empty print statement

while True:
    user_choice = input("Do you want to create a password or read a password? (c/r): ").lower()
    if user_choice in ["c", "r"]:
        break
    print("Invalid choice. Please enter 'c' to create a password or 'r' to read a password.")

if user_choice == "c":
    app_name = input("Which app are you creating a password for? ")
    name = input("Enter your Email/Username (e.g., your email or username): ")
    password = input("Enter your password (e.g., a strong and unique password): ")
    print("Creating a password...")
    with open("database.txt", "a", encoding="utf-8") as file:  # Use append mode
        file.write(f"{app_name} - {name} - {password}\n")
        print("Password created successfully!")        

elif user_choice == "r":
    print("Reading a password...")
    try:
        with open("database.txt", "r", encoding="utf-8") as file:
            content = file.read()
            if content.strip() == "":
                print("No saved passwords found. Please create one first.")
            else:
                print("Your saved password(s):\n" + content)
    except FileNotFoundError:
        print("Error: No database file found.")



