import os
import boto3
import time  # Import time module
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from botocore.exceptions import ClientError

# 1. Download Files from S3
def download_from_s3(file_name, bucket_name, region):
    s3 = boto3.client('s3', region_name=region)
    local_path = os.path.join(os.getcwd(), file_name)
    try:
        s3.download_file(bucket_name, file_name, local_path)
        print(f"Downloaded {file_name} from S3.")
        log_event(f"Downloaded {file_name} from S3.", region)
    except ClientError as e:
        if e.response['Error']['Code'] == "404":
            print(f"Error: {file_name} not found in bucket {bucket_name}.")
        else:
            print(f"Error downloading {file_name}: {e}")
        raise
    return local_path

# 2. Load RSA Private Key
def load_private_key(private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    print("Private key loaded.")
    return private_key

# 3. Decrypt AES Key Using RSA
def decrypt_aes_key_with_rsa(encrypted_aes_key_path, private_key):
    with open(encrypted_aes_key_path, "rb") as f:
        encrypted_key = f.read()

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print("AES key decrypted.")
    return aes_key

# 4. Decrypt File Using AES
def decrypt_file_with_aes(encrypted_file, aes_key):
    with open(encrypted_file, 'rb') as f:
        ciphertext = f.read()

    # Extract IV and ciphertext
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    # Decrypt using AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Save decrypted file
    output_file = encrypted_file.replace(".enc", ".decrypted")
    with open(output_file, "wb") as f:
        f.write(plaintext)

    print(f"File decrypted and saved as {output_file}.")
    return output_file

# 5. Log Event to CloudWatch Logs
def log_event(message, region):
    timestamp = int(round(time.time() * 1000))  # Current timestamp in milliseconds
    log_group_name = "DecryptionLogs"
    log_stream_name = "DecryptionStream"

    logs_client = boto3.client('logs', region_name=region)  # Use the region provided by the user

    try:
        # Create log group and stream if not already present
        logs_client.create_log_group(logGroupName=log_group_name)
    except logs_client.exceptions.ResourceAlreadyExistsException:
        pass  # Log group already exists

    try:
        logs_client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
    except logs_client.exceptions.ResourceAlreadyExistsException:
        pass  # Log stream already exists

    # Put log events
    log_event = {
        'timestamp': timestamp,
        'message': message
    }

    try:
        logs_client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[log_event]
        )
        print(f"Logged event: {message}")
    except Exception as e:
        print(f"Error logging event: {e}")

# Main Decryption Process
def main():
    # Get the AWS region from the user
    region = input("Enter your AWS region (e.g., 'us-east-1'): ")

    # Get the S3 bucket name from the user
    bucket_name = input("Enter your S3 bucket name: ")

    # Files to process
    encrypted_file_name = input("Enter the encrypted file name to decrypt: ")
    encrypted_aes_key_name = input("Enter the AES key file name (e.g., 'aes_key.enc'): ")
    public_key_name = "public_key.pem"  # The public key that will be downloaded if needed

    # Ask user if files need to be downloaded from S3
    download_choice = input("Do you want to download files from S3? (yes/no): ").strip().lower()
    if download_choice == "yes":
        try:
            encrypted_file_name = download_from_s3(encrypted_file_name, bucket_name, region)
            encrypted_aes_key_name = download_from_s3(encrypted_aes_key_name, bucket_name, region)
            public_key_name = download_from_s3(public_key_name, bucket_name, region)
        except ClientError:
            print("Error downloading files. Exiting.")
            return

    # Load RSA private key for decryption (make sure the private key exists in the same directory)
    private_key_file = input("Enter the path to your private key file (e.g., 'private_key.pem'): ")
    private_key = load_private_key(private_key_file)

    # Decrypt AES key with RSA
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key_name, private_key)

    # Decrypt the file using AES
    decrypt_file_with_aes(encrypted_file_name, aes_key)

if _name_ == "_main_":
    main()