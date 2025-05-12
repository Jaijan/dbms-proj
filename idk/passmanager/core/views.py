from django.shortcuts import render
from .models import Credential, UserProfile
from .forms import CredentialForm

def home(request):
    # For demo, use the first user (in production, use the logged-in user)
    user = UserProfile.objects.first()
    if not user:
        user = UserProfile.objects.create(name='Default', pin='0000')

    if request.method == 'POST':
        website = request.POST.get('website')
        username = request.POST.get('username')
        password = request.POST.get('password')
        if website and username and password:
            cred = Credential(user=user, website=website, username=username)
            cred.set_password(password)
            cred.save()
    
    credentials = Credential.objects.filter(user=user)
    # Prepare credentials for JS (decrypted)
    cred_list = [
        {
            'website': c.website,
            'username': c.username,
            'password': c.get_password(),
        } for c in credentials
    ]
    return render(request, 'core/home.html', {
        'credentials': cred_list,
    })
