from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from .models import Credential, UserProfile
from .forms import CredentialForm
import logging
import json

logger = logging.getLogger(__name__)

def signin(request):
    # If user is already logged in, redirect to home
    if request.user.is_authenticated:
        return redirect('home')
        
    if request.method == 'POST':
        # Check if this is a signup form submission
        if 'email' in request.POST:
            # Sign up
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
            messages.success(request, f'Welcome to Password Manager, {username}!')
            return redirect('home')
        else:
            # Sign in
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
            
            if not website:
                return JsonResponse({'success': False, 'error': 'Website is required'})
            
            # Get the user's profile
            user_profile = UserProfile.objects.get(user=request.user)
            
            # Find and delete the credential
            credential = Credential.objects.filter(
                user_profile=user_profile,
                website=website
            ).first()
            
            if credential:
                credential.delete()
                logger.info(f"Password deleted for website: {website}")
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'Credential not found'})
                
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON data'})
        except UserProfile.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User profile not found'})
        except Exception as e:
            logger.error(f"Error deleting password: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})
    
    return JsonResponse({'success': False, 'error': 'Invalid request method'})
