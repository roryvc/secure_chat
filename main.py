import client
import auth

def main():
    """
    Main method for client side
    """
    # Give 3 login attempts
    for i in range(3):
        success, message = auth.run()
        print(message)
        if success:
            break
        if not success and i == 2:
            "Too many failed login attempts... Exiting app..."
            exit()

if __name__ == "__main__":
    main()