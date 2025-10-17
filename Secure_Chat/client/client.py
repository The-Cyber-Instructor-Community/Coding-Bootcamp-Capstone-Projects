import argparse
import threading
from kafka import KafkaProducer, KafkaConsumer
from cryptography.fernet import Fernet
from stego_utils import encode_message_in_image, decode_message_from_image
from db_utils import init_db, save_message, get_all_messages

DB_FILE = "messages.db"

class SecretManager:
    """Manages encryption key loading, generation, and crypto operations."""
    def __init__(self, key_file="secret.key"):
        self.key_file = key_file
        self.key = self._load_or_generate_key()
        self.fernet = Fernet(self.key)

    def _load_or_generate_key(self):
        """Loads a key from a file or generates a new one."""
        try:
            with open(self.key_file, 'rb') as f:
                key = f.read()
            print("Encryption key loaded from file.")
        except FileNotFoundError:
            print("No key file found. Generating a new key...")
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            print(f"New key generated and saved to '{self.key_file}'.")
        return key

    def encrypt_value(self, value: str) -> str:
        """Encrypts a string value."""
        return self.fernet.encrypt(value.encode()).decode()

    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypts an encrypted string value."""
        try:
            return self.fernet.decrypt(encrypted_value.encode()).decode()
        except Exception as e:
            print(f"️Decryption failed: {e}")
            return None

def send_message(producer, topic, manager):
    """Encrypts, hides, and sends a message."""
    text = input("Enter your message: ")
    image_path = input("Enter path to base image: ")

    # Use the manager to encrypt the message
    encrypted = manager.encrypt_value(text)
    stego_image_path = encode_message_in_image(image_path, encrypted)

    with open(stego_image_path, 'rb') as img_file:
        producer.send(topic, img_file.read())
    producer.flush()
    print("[+] Message sent.")

def consume_messages(consumer, manager):
    """Receives, decodes, and decrypts messages."""
    for msg in consumer:
        img_data = msg.value
        stego_file = "received_tmp.png"
        with open(stego_file, 'wb') as f:
            f.write(img_data)

        hidden = decode_message_from_image(stego_file)
        # Use the manager to decrypt the message
        decrypted = manager.decrypt_value(hidden)

        if decrypted:
            print(f"\n📩 New message: {decrypted}\n> ", end="")
            save_message(DB_FILE, hidden)

def consumer_thread(broker, topic, group_id, manager):
    """Sets up and runs the Kafka consumer."""
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=[broker],
        group_id=group_id,
        auto_offset_reset='earliest'
    )
    consume_messages(consumer, manager)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker", required=True)
    parser.add_argument("--topic", required=True)
    args = parser.parse_args()

    init_db(DB_FILE)
    # Create and load the key via SecretManager
    manager = SecretManager()
    
    producer = KafkaProducer(
        bootstrap_servers=[args.broker]
    )

    # Pass the manager instance to the consumer thread
    t = threading.Thread(
        target=consumer_thread,
        args=(args.broker, args.topic, "chat-user1", manager),
        daemon=True
    )
    t.start()

    while True:
        print("\n[1] Send message\n[2] Read history\n[3] Exit")
        choice = input("> ")
        if choice == "1":
            # Pass the manager instance to send_message
            send_message(producer, args.topic, manager)
        elif choice == "2":
            for row in get_all_messages(DB_FILE):
                print(f"{row[0]} | {manager.decrypt_value(row[1])}")
        elif choice == "3":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()