# 🛡️ Secure Chat System (Non-TLS Mode)

This project is a **Secure Chat Proof of Concept** that demonstrates encrypted message exchange between multiple clients using **Kafka** as the message broker.  
Each client can encrypt messages, embed them inside images (steganography), and publish or consume messages from Kafka.  
This version is configured to run in **simplified non-TLS mode** for easier local testing and development.

---

## 📂 Project Structure

secure-chat/
├── client/
│ ├── client.py
│ ├── crypto_utils.py
│ ├── db_utils.py
│ ├── stego_utils.py
│ ├── secret.key
│ └── images/
│ ├── blue.jpg
│ ├── cool.jpg
│ ├── smart.jpg
│ ├── smile.jpg
│ └── think.jpg
│
├── client2/ # Second client (same structure as client/)
│
├── kafka/
│ ├── data/ # Kafka data and logs
│ └── certs/ # TLS certs (not used in non-TLS mode)
│
├── docker-compose.yml # Defines Kafka + Zookeeper stack
├── runtime.txt # Python runtime version
└── README.md # (This file)

## ⚙️ Runtime Environment

The `runtime.txt` file defines the Python version for this project:
 python-3.10

This is used when deploying to platforms like Heroku or ensuring consistent local environments.

You can create a local virtual environment and install dependencies as follows:

pip install cryptography stegano kafka-python

🧠 Client Scripts Overview
1. client.py
Main script that connects to Kafka and handles message publishing and consumption.

Features:

Sends and receives secure messages over Kafka.

Uses local encryption (crypto_utils) and steganography (stego_utils).

Can be configured to simulate multiple users (e.g., client/ and client2/).

Key Config Parameters (Non-TLS Mode):

python
Copy code
bootstrap_servers = "localhost:9092"
security_protocol = "PLAINTEXT"
ssl_cafile = None
ssl_certfile = None
ssl_keyfile = None
Run a client:

bash
Copy code
python client/client.py
You can also run multiple clients simultaneously to simulate conversations.

2. crypto_utils.py
Handles all encryption/decryption logic.

Functions:

generate_key(): Generates and stores an AES encryption key.

encrypt_message(msg): Encrypts messages using the key.

decrypt_message(encrypted_msg): Decrypts messages received from Kafka.

The key is stored locally in secret.key.

3. stego_utils.py
Implements steganography functions to hide messages within images using the stegano library.

Functions:

encode_message(image_path, message, output_image_path)

decode_message(image_path)

This allows hiding an encrypted message inside an image (e.g., blue.jpg) before sending.

4. db_utils.py
Utility functions for storing or retrieving messages from a lightweight local database (SQLite or file-based).

Used primarily for testing persistence and message history.

🐳 Docker Compose Setup (Non-TLS Mode)
The docker-compose.yml file defines a Kafka + Zookeeper stack for local development.

Example Configuration
yaml
Copy code
version: '3.8'
services:
  zookeeper:
    image: wurstmeister/zookeeper
    ports:
      - "2181:2181"

  kafka:
    image: wurstmeister/kafka
    ports:
      - "9092:9092"
    environment:
      KAFKA_BROKER_ID: 1
      KAFKA_ZOOKEEPER_CONNECT: zookeeper:2181
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR: 1
    volumes:
      - ./kafka/data:/var/lib/kafka/data

Start the services

docker-compose up -d

Once Kafka is running, you can connect the clients:

python client/client.py
python client2/client.py

Each client can now send and receive messages through Kafka in plaintext (no TLS required).

👩‍💻 Developer Information
Author: Ruben Barrios
Role: Data & Cloud Solutions Architect
Location: Canada
Expertise: Data Engineering · Cloud Infrastructure · Secure Communications

🧾 License
This project is distributed for educational and research purposes under the MIT License.

🚀 Quick Start Summary

# Start Kafka
docker-compose up -d

# Run clients
python client/client.py
python client2/client.py