import requests
from bs4 import BeautifulSoup
from models.test_headers import TestHeaders
import json
from colorama import Fore, Style
import re

class Crawler:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def fetch_all_links(self, html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        links = [a['href'] for a in soup.find_all('a', href=True)]
        return links
    
    def pretty_print_links(self, links):
        for link in links:
            print(link)
        return links

    def test_headeres(self, headers):
        test_headers = TestHeaders(headers)
        if test_headers.is_safe():
            print("All headers are safe.")
            return ["All headers are safe."]
        else:
            issues = test_headers.get_vulnerable_headers()
            print("Vulnerable headers found:")
            for issue in issues:
                print(f"- {issue}")
            return issues
    
    def crawler(self):
        try:
            response = self.session.get(self.base_url)
            response.raise_for_status()
            headers = response.headers

            print("Testing headers for security vulnerabilities...")
            header_results = self.test_headeres(headers)

            print("Fetching all links from the page...")
            links = self.fetch_all_links(response.text)
            self.pretty_print_links(links)

            ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
            vulnerabilities = {}
            for link in links:
                try:
                    if link.startswith('http'):
                        link_url = link
                    else:
                        link_url = self.base_url.rstrip('/') + '/' + link.lstrip('/')
                    link_response = self.session.get(link_url)
                    link_headers = link_response.headers
                    th = TestHeaders(link_headers)
                    issues = th.get_vulnerable_headers()
                    clean_issues = [ansi_escape.sub('', issue) for issue in issues]
                    if clean_issues:
                        vulnerabilities[link_url] = clean_issues
                except Exception as e:
                    vulnerabilities[link] = [f"Could not be checked: {e}"]

            report = {
                "base_url": self.base_url,
                "links": links,
                "header_test_results": header_results,
                "vulnerabilities": vulnerabilities
            }
            with open("header_vulnerability_report.json", "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            summary = []
            summary.append("Links found:")
            summary.extend(links)
            summary.append("Header test results:")
            summary.extend(header_results)
            if vulnerabilities:
                summary.append("Links with missing headers:" + Style.RESET_ALL)
                for link, issues in vulnerabilities.items():
                    summary.append(f"{link} has missing headers!!:" + Style.RESET_ALL)
                    for issue in issues:
                        summary.append(Fore.RED + f"  - {issue}" + Style.RESET_ALL)
            summary.append("Crawler completed successfully. JSON report written to header_vulnerability_report.json.")
            return "\n".join(summary)
        except requests.RequestException as e:
            print(f"An error occurred: {e}")
            return ""

    