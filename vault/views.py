from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Password
from cryptography.fernet import Fernet
from scanner.models import ScanHistory
import os
import json
import re
from dotenv import load_dotenv

load_dotenv()

f = Fernet(os.getenv('ENCRYPTION_KEY').encode())


def get_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'[0-9]', password): score += 1
    if re.search(r'[^A-Za-z0-9]', password): score += 1
    if score <= 1: return 'weak'
    if score <= 3: return 'medium'
    return 'strong'


@login_required
def dashboard(request):
    passwords = Password.objects.filter(user=request.user)
    urls_scanned = ScanHistory.objects.filter(user=request.user).count()
    decrypted = []
    for p in passwords:
        try:
            decrypted_password = f.decrypt(p.password.encode()).decode()
            strength = get_strength(decrypted_password)
        except:
            decrypted_password = '••••••••'
            strength = 'weak'
        decrypted.append({
            'id': p.id,
            'site_name': p.site_name,
            'username': p.username,
            'password': decrypted_password,
            'strength': strength,
        })
    return render(request, 'dashboard.html', {
        'passwords': decrypted,
        'urls_scanned': urls_scanned,
    })


@login_required
def add_password(request):
    if request.method == 'POST':
        site_name = request.POST['site_name']
        username = request.POST['username']
        password = request.POST['password']
        encrypted = f.encrypt(password.encode()).decode()
        Password.objects.create(
            user=request.user,
            site_name=site_name,
            username=username,
            password=encrypted
        )
        return redirect('dashboard')
    return render(request, 'add_password.html')


@login_required
def delete_password(request, id):
    password = Password.objects.get(id=id, user=request.user)
    password.delete()
    return redirect('dashboard')


@login_required
def reveal_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        pw_id = data.get('id')
        pin = data.get('pin')

        correct_pin = request.user.date_joined.strftime('%d%m%Y')[:4]

        if pin != correct_pin:
            return JsonResponse({'success': False})

        try:
            password = Password.objects.get(id=pw_id, user=request.user)
            decrypted = f.decrypt(password.password.encode()).decode()
            return JsonResponse({'success': True, 'password': decrypted})
        except:
            return JsonResponse({'success': False})