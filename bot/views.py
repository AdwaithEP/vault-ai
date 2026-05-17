import os
import json
from pyexpat import model
import google.generativeai as genai
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

@login_required
def chat(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_message = data.get('message', '')
        model = genai.GenerativeModel('gemini-pro')
        response = model.generate_content(
    f"You are VaultAI, a password security assistant. Help the user with password strength, security advice, and password management tips. User says: {user_message}"
)
        return JsonResponse({'reply': response.text})
    return render(request, 'chat.html')