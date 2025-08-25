
import re
from colorama import Fore, Style

class TestHeaders:
    def __init__(self, headers: dict):
        self.headers = headers

    header_rules = [
        {
            'name': 'X-Content-Type-Options',
            'check': lambda headers: headers.get('X-Content-Type-Options', '').lower() == 'nosniff',
            'issue': 'Issue: X-Content-Type-Options missing or not set to nosniff'
        },
        {
            'name': 'Strict-Transport-Security',
            'check': lambda headers: bool(headers.get('Strict-Transport-Security', '')),
            'issue': 'Issue: Strict-Transport-Security missing'
        },
        {
            'name': 'Content-Security-Policy',
            'check': lambda headers: 'Content-Security-Policy' in headers,
            'issue': 'Issue: Content-Security-Policy missing'
        },
        {
            'name': 'X-Frame-Options',
            'check': lambda headers: headers.get('X-Frame-Options', '').upper() in ['DENY', 'SAMEORIGIN'],
            'issue': 'Issue: X-Frame-Options missing or not set to DENY/SAMEORIGIN'
        },
        {
            'name': 'Referrer-Policy',
            'check': lambda headers: headers.get('Referrer-Policy', '').lower() == 'strict-origin-when-cross-origin',
            'issue': 'Issue: Referrer-Policy missing or not set to strict-origin-when-cross-origin'
        },
        {
            'name': 'Content-Type',
            'check': lambda headers: headers.get('Content-Type', '').lower() == 'text/html; charset=utf-8',
            'issue': 'Issue: Content-Type missing or not set to text/html; charset=UTF-8'
        },
        {
            'name': 'Permissions-Policy',
            'check': lambda headers: 'Permissions-Policy' in headers,
            'issue': 'Issue: Permissions-Policy missing'
        },
        {
            'name': 'Cache-Control',
            'check': lambda headers: 'Cache-Control' in headers and 'no-store' in headers.get('Cache-Control', '').lower(),
            'issue': 'Issue: Cache-Control missing or not set to no-store'
        },

        {
            'name': 'Expires',
            'check': lambda headers: headers.get('Expires', '').lower() == '0',
            'issue': 'Issue: Expires missing or not set to 0'
        },
        {
            'name': 'Access-Control-Allow-Origin',
            'check': lambda headers: headers.get('Access-Control-Allow-Origin', '') == '*',
            'issue': 'Issue: Access-Control-Allow-Origin missing or not set to *'
        },
        {
            'name': 'Cross-Origin-Opener-Policy',
            'check': lambda headers: headers.get('Cross-Origin-Opener-Policy', '').lower() == 'same-origin',
            'issue': 'Issue: Cross-Origin-Opener-Policy missing or not set to same-origin'
        },
    ]

    def get_vulnerable_headers(self):
        issues = []
        for rule in self.header_rules:
            if not rule['check'](self.headers):
                issues.append(rule['issue'])
        return issues
    
    def missing_headers_summary(self):
        issues = self.get_vulnerable_headers()
        if issues:
            return issues
        return []

    def is_safe(self):
        return len(self.get_vulnerable_headers()) == 0
