import re
import json
import os
import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from dotenv import load_dotenv

load_dotenv()

def get_vt_key():
    return os.getenv('VIRUSTOTAL_API_KEY', '')


SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'banking', 'paypal', 'amazon', 'google', 'microsoft',
    'apple', 'netflix', 'password', 'credential', 'wallet', 'crypto',
]

SHORT_URL_DOMAINS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'buff.ly', 'is.gd', 'short.link', 'rebrand.ly',
]


def run_heuristics(url):
    findings = []
    score = 0  # 0=safe, higher=suspicious

    url_lower = url.lower()

    # Check for IP address instead of domain
    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    if re.match(ip_pattern, url):
        findings.append({'type': 'danger', 'msg': 'URL uses an IP address instead of a domain name — common in phishing'})
        score += 40

    # Check for excessive subdomains
    try:
        domain_part = re.sub(r'https?://', '', url).split('/')[0]
        subdomain_count = domain_part.count('.')
        if subdomain_count >= 4:
            findings.append({'type': 'warning', 'msg': f'Unusually many subdomains ({subdomain_count}) — could be domain spoofing'})
            score += 20
    except Exception:
        pass

    # Check for suspicious keywords in URL
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if found_keywords:
        findings.append({'type': 'warning', 'msg': f'Suspicious keywords found: {", ".join(found_keywords[:4])}'})
        score += 15 * min(len(found_keywords), 3)

    # Check for URL shortener
    for short in SHORT_URL_DOMAINS:
        if short in url_lower:
            findings.append({'type': 'warning', 'msg': f'URL shortener detected ({short}) — destination is hidden'})
            score += 25
            break

    # Check for HTTPS
    if not url_lower.startswith('https://'):
        findings.append({'type': 'warning', 'msg': 'Not using HTTPS — connection is not encrypted'})
        score += 15
    else:
        findings.append({'type': 'safe', 'msg': 'Uses HTTPS — connection is encrypted'})

    # Check for @ symbol (used to trick browsers)
    if '@' in url:
        findings.append({'type': 'danger', 'msg': '@ symbol in URL — browsers may ignore everything before it (credential trick)'})
        score += 40

    # Check for double slashes after domain
    if re.search(r'https?://[^/]+/.*//.*', url):
        findings.append({'type': 'warning', 'msg': 'Double slashes in URL path — unusual and potentially obfuscated'})
        score += 15

    # Check URL length
    if len(url) > 100:
        findings.append({'type': 'warning', 'msg': f'Very long URL ({len(url)} chars) — often used to hide the real destination'})
        score += 10

    # Check for hexadecimal encoding
    if '%' in url and re.search(r'%[0-9a-fA-F]{2}', url):
        findings.append({'type': 'warning', 'msg': 'URL contains encoded characters — could be obfuscating malicious content'})
        score += 10

    # Clamp score
    score = min(score, 100)

    if not findings:
        findings.append({'type': 'safe', 'msg': 'No suspicious patterns detected by heuristic scan'})

    return findings, score


def check_virustotal(url):
    VIRUSTOTAL_API_KEY = get_vt_key()
    if not VIRUSTOTAL_API_KEY:
        return None, 'VirusTotal API key not configured'
    try:
        headers = {'x-apikey': get_vt_key()}

        # Submit URL for analysis
        submit_res = requests.post(
            'https://www.virustotal.com/api/v3/urls',
            headers=headers,
            data={'url': url},
            timeout=10
        )
        if submit_res.status_code != 200:
            return None, 'VirusTotal submission failed'

        analysis_id = submit_res.json().get('data', {}).get('id', '')
        if not analysis_id:
            return None, 'No analysis ID returned'

        # Get analysis result
        result_res = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers=headers,
            timeout=10
        )
        if result_res.status_code != 200:
            return None, 'Could not fetch VirusTotal results'

        stats = result_res.json().get('data', {}).get('attributes', {}).get('stats', {})
        return stats, None

    except Exception as e:
        return None, str(e)


@login_required
def scanner(request):
    return render(request, 'scanner.html')


@login_required
def scan_url(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    data = json.loads(request.body)
    url = data.get('url', '').strip()

    if not url:
        return JsonResponse({'error': 'No URL provided'}, status=400)

    # Add scheme if missing
    if not url.startswith('http'):
        url = 'https://' + url

    # Run heuristics
    findings, heuristic_score = run_heuristics(url)

    # Run VirusTotal if API key available
    vt_stats, vt_error = check_virustotal(url)

    # Determine final verdict
    if vt_stats:
        malicious = vt_stats.get('malicious', 0)
        suspicious = vt_stats.get('suspicious', 0)
        if malicious >= 3:
            verdict = 'dangerous'
        elif malicious >= 1 or suspicious >= 2:
            verdict = 'suspicious'
        elif heuristic_score >= 50:
            verdict = 'suspicious'
        else:
            verdict = 'safe'
    else:
        if heuristic_score >= 60:
            verdict = 'dangerous'
        elif heuristic_score >= 25:
            verdict = 'suspicious'
        else:
            verdict = 'safe'

    return JsonResponse({
        'url': url,
        'verdict': verdict,
        'heuristic_score': heuristic_score,
        'findings': findings,
        'vt_stats': vt_stats,
        'vt_error': vt_error,
    })