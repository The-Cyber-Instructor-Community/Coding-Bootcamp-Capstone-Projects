from stegano import lsb
import uuid

def encode_message_in_image(image_path, message):
    output_path = f"stego_{uuid.uuid4().hex}.png"
    secret = lsb.hide(image_path, message)
    secret.save(output_path)
    return output_path

def decode_message_from_image(stego_path):
    return lsb.reveal(stego_path)
