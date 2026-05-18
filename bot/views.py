import os
import json
from groq import Groq
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

@login_required
def chat(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        user_message = data.get('message', '')
        history = data.get('history', [])
        
        messages = [
            {
                "role": "system",
                "content": "You are VaultAI, a password security assistant. Help the user with password strength, security advice, password management tips, and auto categorize passwords into categories like Social Media, Banking, Work, Shopping, Entertainment, or Other when asked."
            }
        ]
        
        messages.extend(history)
        messages.append({"role": "user", "content": user_message})
        
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages
        )
        
        reply = response.choices[0].message.content
        return JsonResponse({'reply': reply})
    
    return render(request, 'chat.html')