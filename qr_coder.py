import streamlit as st
import pandas as pd
import qrcode
from cryptography.fernet import Fernet
from PIL import Image
import os
import base64


# Function to encrypt data and generate QR codes
def encrypt_and_generate_qr(df, save_path):
    # Convert DataFrame to a string
    data = df.to_csv(index=False)

    # Generate a key for encryption
    key = Fernet.generate_key()

    # Create a Fernet cipher
    cipher = Fernet(key)

    # Encrypt the data
    encrypted_data = cipher.encrypt(data.encode())

    # Generate QR code for encrypted data
    qr_encrypted = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr_encrypted.add_data(encrypted_data)
    qr_encrypted.make(fit=True)
    img_encrypted = qr_encrypted.make_image(fill_color="black", back_color="white")
    img_encrypted_path = os.path.join(save_path, 'encrypted_qr_code.png')
    img_encrypted.save(img_encrypted_path)  # Save encrypted QR code as PNG

    # Generate QR code for encryption key
    qr_key = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr_key.add_data(key)
    qr_key.make(fit=True)
    img_key = qr_key.make_image(fill_color="black", back_color="white")
    img_key_path = os.path.join(save_path, 'encryption_key_qr_code.png')
    img_key.save(img_key_path)  # Save encryption key QR code as PNG
    
    return img_encrypted_path, img_key_path
import streamlit as st
import pandas as pd
import qrcode
from cryptography.fernet import Fernet
from PIL import Image
import os
import base64
import cv2

# Function to decrypt encrypted data and generate a new QR code image
def decrypt_and_generate_qr(encrypted_data_qr_path, encryption_key_qr_path, save_path):
    # Read QR code image containing encryption key
    key_image = cv2.imread(encryption_key_qr_path, cv2.IMREAD_GRAYSCALE)
    qr_key_detector = cv2.QRCodeDetector()
    _, key_data, _ = qr_key_detector.detectAndDecodeMulti(key_image)

    # Create a Fernet cipher using the encryption key
    cipher = Fernet(key_data)

    # Read QR code image containing encrypted data
    encrypted_image = cv2.imread(encrypted_data_qr_path, cv2.IMREAD_GRAYSCALE)
    _, encrypted_data, _ = qr_key_detector.detectAndDecodeMulti(encrypted_image)

    # Decrypt the encrypted data
    decrypted_data = cipher.decrypt(encrypted_data.encode()).decode()

    # Create a QR code containing the decrypted data
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(decrypted_data)
    qr.make(fit=True)

    # Create an image from the QR Code instance
    decrypted_qr_img = qr.make_image(fill_color="black", back_color="white")

    # Save the decrypted QR code image
    decrypted_qr_img_path = os.path.join(save_path, 'decrypted_qr_code.png')
    decrypted_qr_img.save(decrypted_qr_img_path)
    
    return decrypted_qr_img_path

# Function to convert image to base64
def image_to_base64(image_path):
    with open(image_path, "rb") as f:
        image_bytes = f.read()
    image_b64 = base64.b64encode(image_bytes).decode('utf-8')
    return image_b64

def main():
    st.title("CSV QR Encryption & Decryption")

    page = st.sidebar.selectbox("Select Page", ["Encryption", "Decryption"])

    save_path = r'E:\TNIBF\imagestenography\results_csv'

    if not os.path.exists(save_path):
        os.makedirs(save_path)

    if page == "Encryption":
        st.header("Encryption Page")
        csv_file = st.file_uploader("Upload CSV file", type=['csv'])

        if csv_file is not None:
            df = pd.read_csv(csv_file)
            encrypted_qr_path, key_qr_path = encrypt_and_generate_qr(df, save_path)
            st.write("Encryption Successful!")
            
            st.markdown("### Download Encrypted QR Code")
            encrypted_qr_b64 = image_to_base64(encrypted_qr_path)
            encrypted_qr_href = f'<a class="btn-download" href="data:image/png;base64,{encrypted_qr_b64}" download="encrypted_qr_code.png">Download Encrypted QR Code</a>'
            st.markdown(encrypted_qr_href, unsafe_allow_html=True)
            
            st.markdown("### Download Encryption Key QR Code")
            key_qr_b64 = image_to_base64(key_qr_path)
            key_qr_href = f'<a class="btn-download" href="data:image/png;base64,{key_qr_b64}" download="encryption_key_qr_code.png">Download Encryption Key QR Code</a>'
            st.markdown(key_qr_href, unsafe_allow_html=True)

    elif page == "Decryption":
        st.header("Decryption Page")
        encrypted_qr_file = st.file_uploader("Upload Encrypted QR Code", type=['png', 'jpg', 'jpeg'])
        key_qr_file = st.file_uploader("Upload Encryption Key QR Code", type=['png', 'jpg', 'jpeg'])

        if encrypted_qr_file is not None and key_qr_file is not None:
            decrypted_qr_img_path = decrypt_and_generate_qr(encrypted_qr_file, key_qr_file, save_path)
            st.write("Decryption Successful!")
            
            st.markdown("### Download Decrypted QR Code")
            decrypted_qr_b64 = image_to_base64(decrypted_qr_img_path)
            decrypted_qr_href = f'<a class="btn-download" href="data:image/png;base64,{decrypted_qr_b64}" download="decrypted_qr_code.png">Download Decrypted QR Code</a>'
            st.markdown(decrypted_qr_href, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
