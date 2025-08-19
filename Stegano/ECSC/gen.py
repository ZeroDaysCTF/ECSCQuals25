#!/usr/bin/env python3
"""
2nd and 3rd LSB Steganography - Hides messages in the second and third least significant bits of image pixels
"""

from PIL import Image
import numpy as np

def text_to_binary(text):
    """Convert text to binary string"""
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary

def hide_messages_lsb(image_path, message_2nd, message_3rd, output_path):
    """Hide messages in 2nd and 3rd LSB of image pixels"""
    
    # Open the image
    img = Image.open(image_path)
    img_array = np.array(img)
    
    # Convert messages to binary
    message_2nd_binary = text_to_binary(message_2nd)
    message_3rd_binary = text_to_binary(message_3rd)
    
    message_2nd_length = len(message_2nd_binary)
    message_3rd_length = len(message_3rd_binary)
    
    # Check if image has enough pixels to hide both messages
    total_pixels = img_array.shape[0] * img_array.shape[1] * img_array.shape[2]
    max_message_length = max(message_2nd_length, message_3rd_length)
    
    if max_message_length > total_pixels:
        raise ValueError("Message too long for this image")
    
    # Flatten the image array for easier manipulation
    flat_img = img_array.flatten()
    
    # Hide the 2nd LSB message
    for i, bit in enumerate(message_2nd_binary):
        # Clear the 2nd LSB and set it to the message bit
        flat_img[i] = (flat_img[i] & 0xFD) | (int(bit) << 1)
    
    # Hide the 3rd LSB message
    for i, bit in enumerate(message_3rd_binary):
        # Clear the 3rd LSB and set it to the message bit
        flat_img[i] = (flat_img[i] & 0xFB) | (int(bit) << 2)
    
    # Reshape back to original dimensions
    stego_img_array = flat_img.reshape(img_array.shape)
    
    # Convert back to PIL Image and save
    stego_img = Image.fromarray(stego_img_array.astype(np.uint8))
    stego_img.save(output_path)
    
    print(f"Message 1 (2nd LSB): '{message_2nd}' - {message_2nd_length} bits")
    print(f"Message 2 (3rd LSB): '{message_3rd}' - {message_3rd_length} bits")
    print(f"Hidden in {output_path}")

def main():
    input_image = "source.jpg"
    output_image = "chall.png"
    message_2nd = "Key: stegano_is_awful"
    message_3rd = "Cipher: XvspdZDNbtd0sYplY3xVdT0j5FSLRg7fcT5IE0RHR1w="
    
    try:
        hide_messages_lsb(input_image, message_2nd, message_3rd, output_image)
        print("Steganography completed successfully!")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
