import json
import socket
import requests
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

def index(request):
    return render(request, 'dashboard/index.html')

@csrf_exempt
def scan(request):
    return render(request, 'dashboard/scan.html')

def ip_intelligence(request):
    return render(request, 'dashboard/ip_intelligence.html')

@csrf_exempt
def api_scan(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        target = data.get('target', '').strip()
        results = {
            'target': target,
            'ip_info': get_ip_info(target),
            'abuse_info': get_abuse_info(target),
            'risk_score': 0,
            'findings': []
        }
        abuse = results['abuse_info']
        if abuse.get('abuseConfidenceScore', 0) > 50:
            results['risk_score'] += 50
            results['findings'].append('⚠️ IP con alto índice de abuso detectado')
        if abuse.get('totalReports', 0) > 10:
            results['risk_score'] += 20
            results['findings'].append('⚠️ Múltiples reportes de abuso')
        if abuse.get('isPublic', False):
            results['findings'].append('ℹ️ IP pública confirmada')
        if abuse.get('usageType') == 'Data Center/Web Hosting/Transit':
            results['risk_score'] += 10
            results['findings'].append('⚠️ IP asociada a datacenter o hosting')
        results['risk_score'] = min(results['risk_score'], 100)
        return JsonResponse(results)
    return JsonResponse({'error': 'Método no permitido'}, status=405)


@csrf_exempt
def api_ip_details(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        ip = data.get('ip', '').strip()

        try:
            resolved = socket.gethostbyname(ip)
        except:
            resolved = ip

        geo = get_ip_info(resolved)
        abuse = get_abuse_info(resolved)

        # Puertos comunes simulados (en producción usarías nmap)
        ports_check = []
        common_ports = [80, 443, 22, 21, 25, 3389, 8080, 8443]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((resolved, port))
                if result == 0:
                    ports_check.append({'port': port, 'status': 'open'})
                sock.close()
            except:
                pass

        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(resolved)[0]
        except:
            hostname = 'N/A'

        risk_score = 0
        findings = []
        tags = []

        score = abuse.get('abuseConfidenceScore', 0)
        reports = abuse.get('totalReports', 0)

        if score > 80:
            risk_score += 60
            findings.append('🚨 IP con altísimo índice de abuso')
            tags.append({'label': 'MALICIOUS', 'type': 'red'})
        elif score > 50:
            risk_score += 40
            findings.append('⚠️ IP con alto índice de abuso')
            tags.append({'label': 'SUSPICIOUS', 'type': 'yellow'})
        elif score > 20:
            risk_score += 20
            findings.append('⚠️ IP con abuso moderado')
            tags.append({'label': 'MODERATE', 'type': 'yellow'})

        if reports > 100:
            risk_score += 20
            findings.append(f'⚠️ {reports} reportes de abuso registrados')
        elif reports > 10:
            risk_score += 10
            findings.append(f'ℹ️ {reports} reportes de abuso registrados')

        if abuse.get('isPublic'):
            findings.append('ℹ️ IP pública confirmada')
            tags.append({'label': 'PUBLIC', 'type': 'blue'})

        usage = abuse.get('usageType', '')
        if 'Data Center' in usage or 'Hosting' in usage:
            risk_score += 10
            findings.append('⚠️ IP asociada a datacenter/hosting')
            tags.append({'label': 'DATACENTER', 'type': 'yellow'})
        elif usage:
            findings.append(f'ℹ️ Tipo de uso: {usage}')

        if len(ports_check) > 3:
            risk_score += 10
            findings.append(f'⚠️ {len(ports_check)} puertos abiertos detectados')

        if not findings:
            findings.append('✅ Sin indicadores de riesgo detectados')
            tags.append({'label': 'CLEAN', 'type': 'green'})

        risk_score = min(risk_score, 100)

        return JsonResponse({
            'ip': resolved,
            'target': ip,
            'hostname': hostname,
            'geo': geo,
            'abuse': abuse,
            'ports': ports_check,
            'risk_score': risk_score,
            'findings': findings,
            'tags': tags,
        })

    return JsonResponse({'error': 'Método no permitido'}, status=405)


def get_ip_info(target):
    try:
        ip = socket.gethostbyname(target)
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': ip,
                'country': data.get('country', 'N/A'),
                'countryCode': data.get('countryCode', 'N/A'),
                'city': data.get('city', 'N/A'),
                'region': data.get('regionName', 'N/A'),
                'org': data.get('org', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'as': data.get('as', 'N/A'),
                'lat': data.get('lat', 0),
                'lon': data.get('lon', 0),
                'timezone': data.get('timezone', 'N/A'),
            }
    except Exception as e:
        return {'ip': target, 'error': str(e)}
    return {}


def get_abuse_info(target):
    try:
        ip = socket.gethostbyname(target)
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': '4f474a1a76264729ca754f3f5e48fd54de5f9eb1fea43b8f91388a3e8935b8dce22a9f0d19f54c24', 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=5
        )
        if response.status_code == 200:
            return response.json().get('data', {})
    except:
        pass
    return {
        'abuseConfidenceScore': 0,
        'totalReports': 0,
        'isPublic': True,
        'usageType': 'N/A',
        'isp': 'N/A',
        'countryCode': 'N/A',
        'numDistinctUsers': 0,
        'lastReportedAt': 'N/A',
    }