import os
import boto3
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
import time

def log_event_to_cloudwatch(log_group, log_stream, message, iam_user):
    """Log detailed events to CloudWatch Logs"""
    logs_client = boto3.client('logs')

    try:
        # Create Log Group if not exists
        try:
            logs_client.create_log_group(logGroupName=log_group)
        except logs_client.exceptions.ResourceAlreadyExistsException:
            pass  # Log group already exists

        # Create Log Stream if not exists
        try:
            logs_client.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
        except logs_client.exceptions.ResourceAlreadyExistsException:
            pass  # Log stream already exists

        # Describe log streams to get the sequence token
        response = logs_client.describe_log_streams(
            logGroupName=log_group,
            logStreamNamePrefix=log_stream,
            limit=1
        )

        if len(response['logStreams']) > 0:
            sequence_token = response['logStreams'][0].get('uploadSequenceToken', None)
        else:
            sequence_token = None

        # Include IAM user in the log event
        full_message = f"Action performed by IAM user: {iam_user}. {message}"

        log_event = {
            'timestamp': int(round(time.time() * 1000)),
            'message': full_message
        }

        if sequence_token:
            logs_client.put_log_events(
                logGroupName=log_group,
                logStreamName=log_stream,
                logEvents=[log_event],
                sequenceToken=sequence_token
            )
        else:
            logs_client.put_log_events(
                logGroupName=log_group,
                logStreamName=log_stream,
                logEvents=[log_event]
            )

        print("Log event sent to CloudWatch.")

    except Exception as e:
        print(f"Error logging event: {e}")

# Other helper functions

def generate_rsa_keys(log_group, log_stream, iam_user):
    """Generate RSA public and private keys."""
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        print("Generating new RSA key pair...")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open("private_key.pem", "wb") as private_pem:
            private_pem.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open("public_key.pem", "wb") as public_pem:
            public_pem.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("RSA keys generated and saved.")
        log_event_to_cloudwatch(log_group, log_stream, "Generated RSA key pair.", iam_user)
    else:
        print("RSA keys already exist.")
        log_event_to_cloudwatch(log_group, log_stream, "RSA keys already exist.", iam_user)

def encrypt_file_with_aes(input_file, aes_key, log_group, log_stream, iam_user):
    """Encrypt the input file with AES."""
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(plaintext) + encryptor.finalize()

    encrypted_file = input_file + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(ciphertext)

    print(f"File {input_file} encrypted to {encrypted_file}.")
    log_event_to_cloudwatch(log_group, log_stream, f"Encrypted file {input_file}.", iam_user)
    return encrypted_file

def encrypt_aes_key_with_rsa(aes_key, public_key, log_group, log_stream, iam_user):
    """Encrypt the AES key with the RSA public key."""
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_key_path = "aes_key.enc"
    with open(encrypted_key_path, "wb") as f:
        f.write(encrypted_key)

    print("AES key encrypted and saved as 'aes_key.enc'.")
    log_event_to_cloudwatch(log_group, log_stream, "Encrypted AES key and saved as 'aes_key.enc'.", iam_user)
    return encrypted_key_path

def upload_to_s3(file_path, bucket_name, log_group, log_stream, iam_user):
    """Upload a file to S3 bucket."""
    s3 = boto3.client('s3')
    file_name = os.path.basename(file_path)
    try:
        s3.upload_file(file_path, bucket_name, file_name)
        print(f"Uploaded {file_name} to S3 bucket {bucket_name}.")
        log_event_to_cloudwatch(log_group, log_stream, f"Uploaded {file_name} to S3 bucket {bucket_name}.", iam_user)
    except Exception as e:
        print(f"Error uploading file {file_name} to S3: {e}")
        log_event_to_cloudwatch(log_group, log_stream, f"Error uploading file {file_name} to S3: {e}", iam_user)

def get_iam_user():
    """Retrieve the current IAM user."""
    sts_client = boto3.client('sts')
    try:
        response = sts_client.get_caller_identity()
        iam_user_arn = response['Arn']
        iam_user_name = iam_user_arn.split('/')[-1]
        return iam_user_name
    except Exception as e:
        print(f"Error retrieving IAM user information: {e}")
        return "Unknown"

def main():
    # Get Log Group and Stream Name from User
    log_group = input("Enter the CloudWatch Log Group name: ")
    log_stream = input("Enter the CloudWatch Log Stream name: ")

    # Get the IAM user who performed the action
    iam_user = get_iam_user()

    # Generate RSA Keys if not exist
    generate_rsa_keys(log_group, log_stream, iam_user)

    # Get User Input for File to Encrypt
    input_file = input("Enter the path of the file to encrypt: ")
    if not os.path.exists(input_file):
        print("File not found! Please try again.")
        log_event_to_cloudwatch(log_group, log_stream, f"File {input_file} not found.", iam_user)
        return

    # Generate AES Key
    aes_key = os.urandom(32)  # 256-bit AES Key

    # Encrypt File with AES
    encrypted_file = encrypt_file_with_aes(input_file, aes_key, log_group, log_stream, iam_user)

    # Load the RSA public key
    with open("public_key.pem", "rb") as f:
        public_key_pem = f.read()
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Encrypt AES Key with RSA
    encrypted_aes_key_path = encrypt_aes_key_with_rsa(aes_key, public_key, log_group, log_stream, iam_user)

    # Get the S3 bucket name from the user
    bucket_name = input("Enter your S3 bucket name: ")

    # Upload Encrypted Files to S3
    upload_to_s3(encrypted_file, bucket_name, log_group, log_stream, iam_user)
    upload_to_s3(encrypted_aes_key_path, bucket_name, log_group, log_stream, iam_user)
    upload_to_s3("public_key.pem", bucket_name, log_group, log_stream, iam_user)

    print("Encryption complete and files uploaded to S3.")
    log_event_to_cloudwatch(log_group, log_stream, f"Encryption process complete for file {input_file}.", iam_user)

if _name_ == "_main_":
    main()