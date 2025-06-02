from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse, FileResponse
from .models import Credential, UserProfile, Document
from .forms import CredentialForm
import logging
import json
import random
from django.core.mail import send_mail
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.conf import settings
from django.core.exceptions import ValidationError
from django_otp import devices_for_user
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode
import io
import base64

logger = logging.getLogger(__name__)

def signin(request):
    # If user is already logged in, redirect to home
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        # TOTP-based login
        if 'email' in request.POST and 'otp' in request.POST:
            email = request.POST.get('email')
            otp = request.POST.get('otp')
            try:
                user = User.objects.get(email=email)
                user_profile = UserProfile.objects.get(user=user)
                device = user_profile.otp_device
                
                if device and device.verify_token(otp):
                    login(request, user)
                    messages.success(request, f'Welcome back, {user.username}!')
                    return redirect('home')
                else:
                    messages.error(request, 'Invalid OTP')
            except User.DoesNotExist:
                messages.error(request, 'No user found with this email.')
            except UserProfile.DoesNotExist:
                messages.error(request, 'User profile not found.')
            return render(request, 'core/signin.html')
            
        # Signup
        if 'email' in request.POST and 'username' in request.POST and 'password' in request.POST:
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            if password != confirm_password:
                messages.error(request, 'Passwords do not match')
                return render(request, 'core/signin.html')
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists')
                return render(request, 'core/signin.html')
            user = User.objects.create_user(username=username, email=email, password=password)
            UserProfile.objects.create(user=user, name=username, pin='0000')
            login(request, user)
            messages.success(request, f'Welcome to PAMS, {username}!')
            return redirect('home')
            
        # Password-based login (legacy, fallback)
        if 'username' in request.POST and 'password' in request.POST:
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect('home')
            else:
                messages.error(request, 'Invalid username or password')
    return render(request, 'core/signin.html')

def signout(request):
    if request.user.is_authenticated:
        logout(request)
        messages.info(request, 'You have been signed out successfully')
    return redirect('signin')

@login_required(login_url='signin')
def home(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
    except UserProfile.DoesNotExist:
        user_profile = UserProfile.objects.create(user=request.user, name=request.user.username, pin='0000')

    if request.method == 'POST':
        website = request.POST.get('website')
        username = request.POST.get('username')
        password = request.POST.get('password')
        if website and username and password:
            logger.info(f"Saving password for website: {website}")
            cred = Credential(user=user_profile, website=website, username=username)
            cred.set_password(password)
            cred.save()
            messages.success(request, f'Password saved for {website}')
    
    credentials = Credential.objects.filter(user=user_profile)
    logger.info(f"Found {credentials.count()} credentials for user {request.user.username}")
    
    # Prepare credentials for JS (decrypted)
    cred_list = []
    for c in credentials:
        try:
            decrypted_password = c.get_password()
            logger.info(f"Successfully decrypted password for {c.website}")
            cred_list.append({
                'website': c.website,
                'username': c.username,
                'password': decrypted_password,
            })
        except Exception as e:
            logger.error(f"Error decrypting password for {c.website}: {str(e)}")
            continue  # Skip this credential if decryption fails
    
    logger.info(f"Rendering template with {len(cred_list)} credentials")
    logger.info(f"Credential data: {cred_list}")
    
    # Convert credentials to JSON string for JavaScript
    credentials_json = json.dumps(cred_list)
    logger.info(f"JSON credentials: {credentials_json}")
    
    return render(request, 'core/home.html', {
        'credentials': credentials_json,  # Pass as JSON string
    })

@login_required(login_url='signin')
def get_credentials(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        credentials = Credential.objects.filter(user=user_profile)
        logger.info(f"Found {credentials.count()} credentials for user {request.user.username}")
        
        cred_list = []
        for c in credentials:
            try:
                decrypted_password = c.get_password()
                logger.info(f"Successfully decrypted password for {c.website}")
                cred_list.append({
                    'website': c.website,
                    'username': c.username,
                    'password': decrypted_password,
                })
            except Exception as e:
                logger.error(f"Error decrypting password for {c.website}: {str(e)}")
        
        return JsonResponse({'credentials': cred_list})
    except UserProfile.DoesNotExist:
        logger.warning(f"No UserProfile found for user {request.user.username}")
        return JsonResponse({'credentials': []})

@login_required
def delete_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            website = data.get('website')
            logger.info(f"Delete request for website: {website} by user: {request.user}")
            if not website:
                logger.warning("No website provided in delete request.")
                return JsonResponse({'success': False, 'error': 'Website is required'})
            # Get the user's profile
            user_profile = UserProfile.objects.get(user=request.user)
            logger.info(f"UserProfile found: {user_profile}")
            # Find and delete the credential
            credential = Credential.objects.filter(
                user=user_profile,
                website=website
            ).first()
            if credential:
                logger.info(f"Credential found for deletion: {credential}")
                credential.delete()
                logger.info(f"Password deleted for website: {website}")
                return JsonResponse({'success': True})
            else:
                logger.warning(f"No credential found for website: {website} and user: {user_profile}")
                return JsonResponse({'success': False, 'error': 'Credential not found'})
        except json.JSONDecodeError:
            logger.error("Invalid JSON data in delete request.")
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
        except UserProfile.DoesNotExist:
            logger.error("User profile not found in delete request.")
            return JsonResponse({'success': False, 'error': 'User profile not found'})
        except Exception as e:
            logger.error(f"Error deleting password: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})
    logger.warning("Invalid request method for delete_password.")
    return JsonResponse({'success': False, 'error': 'Invalid request method'})

def generate_otp():
    return str(random.randint(100000, 999999))

@csrf_exempt
@require_POST
def send_login_otp(request):
    email = request.POST.get('email')
    if not email:
        return JsonResponse({'success': False, 'error': 'Email is required.'}, status=400)
    otp = generate_otp()
    request.session['login_otp'] = otp
    request.session['login_otp_email'] = email
    request.session['login_otp_time'] = timezone.now().isoformat()
    try:
        send_mail(
            'Your PAMS Login OTP',
            f'Your OTP for logging in to PAMS is: {otp}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        return JsonResponse({'success': True, 'message': 'OTP sent to your email.'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@csrf_exempt
@require_POST
def upload_document(request):
    try:
        if 'file' not in request.FILES:
            return JsonResponse({'success': False, 'error': 'No file provided'}, status=400)
        
        file = request.FILES['file']
        if file.size > 10 * 1024 * 1024:  # 10MB limit
            return JsonResponse({'success': False, 'error': 'File size must be no more than 10MB'}, status=400)
        
        user_profile = UserProfile.objects.get(user=request.user)
        document = Document(
            user=user_profile,
            file=file,
            filename=file.name
        )
        document.full_clean()  # This will trigger the clean() method and validate file size
        document.save()
        
        return JsonResponse({
            'success': True,
            'message': 'File uploaded successfully',
            'document': {
                'id': document.id,
                'filename': document.filename,
                'uploaded_at': document.uploaded_at.isoformat()
            }
        })
    except ValidationError as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)
    except Exception as e:
        logger.error(f"Error uploading document: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def get_documents(request):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        documents = Document.objects.filter(user=user_profile).order_by('-uploaded_at')
        return JsonResponse({
            'success': True,
            'documents': [{
                'id': doc.id,
                'filename': doc.filename,
                'uploaded_at': doc.uploaded_at.isoformat()
            } for doc in documents]
        })
    except Exception as e:
        logger.error(f"Error fetching documents: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def delete_document(request, document_id):
    try:
        user_profile = UserProfile.objects.get(user=request.user)
        document = Document.objects.get(id=document_id, user=user_profile)
        document.delete()
        return JsonResponse({'success': True, 'message': 'Document deleted successfully'})
    except Document.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)
    except Exception as e:
        logger.error(f"Error deleting document: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@csrf_exempt
@require_POST
def setup_otp(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        if not email:
            return JsonResponse({'success': False, 'error': 'Email is required'}, status=400)

        try:
            user = User.objects.get(email=email)
            user_profile, created = UserProfile.objects.get_or_create(
                user=user,
                defaults={'name': user.username, 'pin': '0000'}
            )
            
            device = user_profile.setup_otp()
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(device.config_url)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            qr_code = base64.b64encode(buffer.getvalue()).decode()
            
            return JsonResponse({
                'success': True,
                'qr_code': qr_code,
                'secret': device.key
            })
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'No user found with this email'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error setting up OTP: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@csrf_exempt
@require_POST
def verify_otp(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        otp = data.get('otp')
        
        if not email or not otp:
            return JsonResponse({'success': False, 'error': 'Email and OTP are required'}, status=400)
        
        try:
            user = User.objects.get(email=email)
            user_profile = UserProfile.objects.get(user=user)
            device = user_profile.otp_device
            
            if not device:
                return JsonResponse({'success': False, 'error': 'OTP device not set up'}, status=400)
            
            if device.verify_token(otp):
                # Log the user in
                login(request, user)
                return JsonResponse({
                    'success': True,
                    'message': 'OTP verified successfully',
                    'redirect': '/home/'
                })
            else:
                return JsonResponse({'success': False, 'error': 'Invalid OTP'}, status=400)
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
        except UserProfile.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User profile not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error verifying OTP: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@csrf_exempt
@require_POST
def verify_document_otp(request):
    try:
        data = json.loads(request.body)
        document_id = data.get('document_id')
        otp = data.get('otp')
        
        if not document_id or not otp:
            return JsonResponse({'success': False, 'error': 'Document ID and OTP are required'}, status=400)
        
        try:
            document = Document.objects.get(id=document_id, user__user=request.user)
            user_profile = document.user
            device = user_profile.otp_device
            
            if not device:
                return JsonResponse({'success': False, 'error': 'OTP device not set up'}, status=400)
            
            if device.verify_token(otp):
                # Store verification in session
                request.session[f'document_verified_{document_id}'] = True
                return JsonResponse({'success': True, 'message': 'OTP verified successfully'})
            else:
                return JsonResponse({'success': False, 'error': 'Invalid OTP'}, status=400)
        except Document.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON data'}, status=400)
    except Exception as e:
        logger.error(f"Error verifying document OTP: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def view_document(request, document_id):
    try:
        document = Document.objects.get(id=document_id, user__user=request.user)
        
        # Check if document is verified
        if not request.session.get(f'document_verified_{document_id}'):
            return JsonResponse({'success': False, 'error': 'Document access not verified'}, status=403)
        
        # Clear verification after use
        del request.session[f'document_verified_{document_id}']
        
        # Check if file exists
        if not document.file:
            return JsonResponse({'success': False, 'error': 'File not found'}, status=404)
            
        # Get file extension and set appropriate content type
        file_extension = document.filename.split('.')[-1].lower()
        content_types = {
            'pdf': 'application/pdf',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'txt': 'text/plain',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        }
        content_type = content_types.get(file_extension, 'application/octet-stream')
        
        # Serve the file
        response = FileResponse(document.file, as_attachment=False)
        response['Content-Type'] = content_type
        response['Content-Disposition'] = f'inline; filename="{document.filename}"'
        return response
    except Document.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)
    except Exception as e:
        logger.error(f"Error viewing document: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def download_document(request, document_id):
    try:
        document = Document.objects.get(id=document_id, user__user=request.user)
        
        # Check if document is verified
        if not request.session.get(f'document_verified_{document_id}'):
            return JsonResponse({'success': False, 'error': 'Document access not verified'}, status=403)
        
        # Clear verification after use
        del request.session[f'document_verified_{document_id}']
        
        # Check if file exists
        if not document.file:
            return JsonResponse({'success': False, 'error': 'File not found'}, status=404)
            
        # Get file extension and set appropriate content type
        file_extension = document.filename.split('.')[-1].lower()
        content_types = {
            'pdf': 'application/pdf',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'txt': 'text/plain',
            'doc': 'application/msword',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        }
        content_type = content_types.get(file_extension, 'application/octet-stream')
        
        # Serve the file as an attachment
        response = FileResponse(document.file, as_attachment=True)
        response['Content-Type'] = content_type
        response['Content-Disposition'] = f'attachment; filename="{document.filename}"'
        return response
    except Document.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)
    except Exception as e:
        logger.error(f"Error downloading document: {str(e)}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
