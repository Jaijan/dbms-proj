from django.db import models
from cryptography.fernet import Fernet
import base64
import os

# Key for encryption (in production store this securely!)
key = base64.urlsafe_b64encode(os.urandom(32))
fernet = Fernet(key)

class UserProfile(models.Model):
    name = models.CharField(max_length=100)
    pin = models.CharField(max_length=4)

class Credential(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    website = models.CharField(max_length=100)
    username = models.CharField(max_length=100)
    encrypted_password = models.BinaryField()

    def set_password(self, raw_password):
        self.encrypted_password = fernet.encrypt(raw_password.encode())

    def get_password(self):
        return fernet.decrypt(self.encrypted_password).decode()
