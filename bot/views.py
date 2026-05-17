import os
import json
from google import genai
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv('GEMINI_API_KEY'))

@login_required
def chat(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_message = data.get('message', '')
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=f"You are VaultAI, a password security assistant. Help the user with password strength, security advice, and password management tips. User says: {user_message}"
        )
        return JsonResponse({'reply': response.text})
    return render(request, 'chat.html')