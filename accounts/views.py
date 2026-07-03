from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .models import UserProfile

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'login.html', {'error': 'Wrong credentials'})
    return render(request, 'login.html')

def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        if User.objects.filter(username=username).exists():
            return render(request, 'signup.html', {'error': 'Username already exists'})
        user = User.objects.create_user(username=username, password=password)
        UserProfile.objects.create(user=user)
        login(request, user)
        return redirect('dashboard')
    return render(request, 'signup.html')

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def settings_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    success = False
    error = None

    if request.method == 'POST':
        pin = request.POST.get('pin', '')
        confirm_pin = request.POST.get('confirm_pin', '')
        if len(pin) != 4 or not pin.isdigit():
            error = 'PIN must be exactly 4 digits'
        elif pin != confirm_pin:
            error = 'PINs do not match'
        else:
            profile.vault_pin = pin
            profile.save()
            success = True

    return render(request, 'settings.html', {
        'has_pin': bool(profile.vault_pin),
        'success': success,
        'error': error,
    })