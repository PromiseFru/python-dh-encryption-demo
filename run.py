import argparse
import logging

from diffie_hellman import generate_dh_parameters, generate_keypair, generate_shared_key
from encryption import derive_key, encrypt_message, decrypt_message

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_simulation(sender_name, receiver_name):
    logger.info("Starting simulation...")

    parameters = generate_dh_parameters()

    sender_private_key, sender_public_key = generate_keypair(parameters)

    print(f"Hello, {sender_name}!")
    print("Your public key is:", sender_public_key)

    receiver_public_key = int(input(f"Enter {receiver_name}'s public key: "))

    shared_key = generate_shared_key(sender_private_key, receiver_public_key)

    print("Share key is:", shared_key.hex())

    encryption_key = derive_key(shared_key)

    action = (
        input("Do you want to encrypt or decrypt a message? (encrypt/decrypt): ")
        .strip()
        .lower()
    )

    if action == "encrypt":
        message = input("Enter the message to encrypt: ").encode("utf-8")
        encrypted_message = encrypt_message(message, encryption_key)
        print("Your Encrypted Message:", encrypted_message.hex())
    elif action == "decrypt":
        encrypted_message = bytes.fromhex(
            input(
                "Enter the encrypted message to decrypt (in hexadecimal format): "
            ).strip()
        )
        decrypted_message = decrypt_message(encrypted_message, encryption_key)
        print("Your Decrypted Message:", decrypted_message.decode("utf-8"))
    else:
        print("Invalid action. Please choose either 'encrypt' or 'decrypt'.")


def main():
    parser = argparse.ArgumentParser(
        description="Diffie-Hellman Key Exchange Simulation"
    )
    parser.add_argument("--sender", default="Alice", help="Name of the sender")
    parser.add_argument("--receiver", default="Bob", help="Name of the receiver")
    args = parser.parse_args()

    run_simulation(args.sender, args.receiver)


if __name__ == "__main__":
    main()
