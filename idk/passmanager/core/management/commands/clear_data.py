from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from core.models import UserProfile, Credential, Document
import os
import shutil

class Command(BaseCommand):
    help = 'Clears all user data including users, profiles, credentials, and documents'

    def handle(self, *args, **options):
        # Delete all documents and their files
        documents = Document.objects.all()
        for doc in documents:
            if doc.file:
                try:
                    if os.path.isfile(doc.file.path):
                        os.remove(doc.file.path)
                except Exception as e:
                    self.stdout.write(self.style.WARNING(f'Error deleting file {doc.file.path}: {str(e)}'))
        documents.delete()
        self.stdout.write(self.style.SUCCESS('Deleted all documents'))

        # Delete all credentials
        Credential.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Deleted all credentials'))

        # Delete all user profiles
        UserProfile.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Deleted all user profiles'))

        # Delete all users
        User.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Deleted all users'))

        # Clear media directory
        media_dir = 'media'
        if os.path.exists(media_dir):
            try:
                shutil.rmtree(media_dir)
                os.makedirs(media_dir)
                self.stdout.write(self.style.SUCCESS('Cleared media directory'))
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'Error clearing media directory: {str(e)}'))

        self.stdout.write(self.style.SUCCESS('Successfully cleared all data')) 