from django.db import models
from django.contrib.auth.models import User
from cryptography.fernet import Fernet
import base64
import os
import logging

logger = logging.getLogger(__name__)

def get_encryption_key():
    key_file = 'encryption.key'
    try:
        if os.path.exists(key_file):
            logger.info("Loading existing encryption key")
            with open(key_file, 'rb') as f:
                key = f.read()
                logger.info("Successfully loaded encryption key")
                return key
        else:
            logger.info("Generating new encryption key")
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            logger.info("Successfully generated and saved new encryption key")
            return key
    except Exception as e:
        logger.error(f"Error handling encryption key: {str(e)}")
        raise

# Initialize Fernet with persistent key
try:
    fernet = Fernet(get_encryption_key())
    logger.info("Successfully initialized Fernet with encryption key")
except Exception as e:
    logger.error(f"Failed to initialize Fernet: {str(e)}")
    raise

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    pin = models.CharField(max_length=4)

class Credential(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    website = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    encrypted_password = models.BinaryField()

    def set_password(self, raw_password):
        try:
            logger.info(f"Encrypting password for {self.website}")
            self.encrypted_password = fernet.encrypt(raw_password.encode())
            logger.info(f"Successfully encrypted password for {self.website}")
        except Exception as e:
            logger.error(f"Error encrypting password for {self.website}: {str(e)}")
            raise

    def get_password(self):
        try:
            logger.info(f"Decrypting password for {self.website}")
            decrypted = fernet.decrypt(self.encrypted_password).decode()
            logger.info(f"Successfully decrypted password for {self.website}")
            return decrypted
        except Exception as e:
            logger.error(f"Error decrypting password for {self.website}: {str(e)}")
            raise
