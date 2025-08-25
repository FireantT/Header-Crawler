from models.crawler import Crawler
from models.test_headers import TestHeaders
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from PySide6.QtCore import QTimer, QThread, Signal
import sys
import re
from html import escape
import json

class CrawlerApp(QWidget):
    class WorkerThread(QThread):
        finished = Signal(str, dict)
        def __init__(self, input_link, parent=None):
            super().__init__(parent)
            self.input_link = input_link
            self.crawler = Crawler(self.input_link)
        def run(self):
            result, report = self.parent().get_crawler_report(self.crawler)
            self.finished.emit(result, report)
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HTTP Header Crawler")
        self.setGeometry(100, 100, 700, 500)
        layout = QVBoxLayout()

        self.label = QLabel("Enter the URL to crawl:")
        layout.addWidget(self.label)

        self.url_input = QLineEdit()
        layout.addWidget(self.url_input)

        self.crawl_button = QPushButton("Start Crawler")
        self.crawl_button.clicked.connect(self.run_crawler)
        layout.addWidget(self.crawl_button)

        self.export_button = QPushButton("Export Report to JSON")
        self.export_button.clicked.connect(self.export_json)
        self.export_button.setEnabled(False)
        layout.addWidget(self.export_button)

        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)
        layout.addWidget(self.result_area)

        self.setLayout(layout)

        self.last_report = None

        self.loading_timer = QTimer()
        self.loading_timer.timeout.connect(self.update_loading)
        self.loading_frames = ['.']
        self.loading_index = 0
        self.is_loading = False

    def run_crawler(self):
        input_link = self.url_input.text().strip()
        if not input_link:
            self.result_area.setText("Please enter a URL.")
            self.export_button.setEnabled(False)
            return
        if not input_link.startswith('http'):
            input_link = 'http://' + input_link
        self.is_loading = True
        self.loading_index = 0
        self.result_area.setText("Starting crawler...\n")
        self.loading_timer.start(100)
        self.worker = self.WorkerThread(input_link, parent=self)
        self.worker.finished.connect(self.on_crawler_finished)
        self.worker.start()

    def update_loading(self):
        if self.is_loading:
            current_text = self.result_area.toPlainText().split('\n')[0]
            spinner = self.loading_frames[self.loading_index % len(self.loading_frames)]
            self.result_area.setText(f"{current_text} {spinner}")
            self.loading_index += 1
        else:
            self.loading_timer.stop()

    def on_crawler_finished(self, result, report):
        self.last_report = report
        self.export_button.setEnabled(True)
        html_result = self.highlight_issues_html(result, report)
        self.result_area.setHtml(html_result)
        self.is_loading = False

    def get_crawler_report(self, crawler):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        links = []
        vulnerabilities = {}
        header_results = []
        base_url = crawler.base_url
        response = crawler.session.get(base_url)
        response.raise_for_status()
        headers = response.headers
        header_results = crawler.test_headeres(headers)
        html = response.text
        links = crawler.fetch_all_links(html)
        crawler.pretty_print_links(links)
        for link in links:
            try:
                if link.startswith('http'):
                    link_url = link
                else:
                    link_url = base_url.rstrip('/') + '/' + link.lstrip('/')
                link_response = crawler.session.get(link_url)
                link_headers = link_response.headers
                th = TestHeaders(link_headers)
                issues = th.get_vulnerable_headers()
                clean_issues = [ansi_escape.sub('', issue) for issue in issues]
                if clean_issues:
                    vulnerabilities[link_url] = clean_issues
            except Exception as e:
                vulnerabilities[link] = [f"Could not be checked: {e}"]
        report = {
            "base_url": base_url,
            "links": links,
            "header_test_results": [ansi_escape.sub('', r) for r in header_results],
            "vulnerabilities": vulnerabilities
        }
        summary = []
        summary.append("Header test results:")
        summary.extend(header_results)
        if vulnerabilities:
            summary.append("Links vulnerable due to missing headers:")
            for link, issues in vulnerabilities.items():
                summary.append(f"{link} is vulnerable:")
                for issue in issues:
                    summary.append(f"  - {issue}")
        summary.append("Crawler completed successfully. JSON report can be exported.")
        return "\n".join(summary), report

    def highlight_issues_html(self, text, report):
        lines = text.split('\n')
        html_lines = []
        vulnerable_links = set(report['vulnerabilities'].keys()) if report and 'vulnerabilities' in report else set()
        for line in lines:
            def make_links_clickable(s):
                return re.sub(r'(https?://[\w\-\.\:/\?\#\[\]@!$&\'()*+,;=%]+)', r'<a href="\1">\1</a>', s)

            if line.strip().startswith('Links vulnerable due to missing headers:'):
                html_lines.append(f'<span style="color:black; font-weight:bold;">{escape(line)}</span>')
            elif line.strip().endswith('is vulnerable:'):
                link_part = line.split(' is vulnerable:')[0]
                if link_part.startswith('http'):
                    link_html = f'<a href="{escape(link_part)}">{escape(link_part)}</a>'
                else:
                    link_html = escape(link_part)
                html_lines.append(f'{link_html} <span style="color:black;">is vulnerable:</span>')
            elif line.strip().startswith('- Issue:') or line.strip().startswith('  - Issue:') or line.strip().startswith('  -'):
                html_lines.append(f'<span style="color:red;">{escape(line)}</span>')
            elif line.strip().startswith('Crawler completed successfully'):
                html_lines.append(f'<span style="color:green;">{escape(line)}</span>')
            else:
                html_lines.append(make_links_clickable(escape(line)))
        return '<br>'.join(html_lines)

    def export_json(self):
        if self.last_report:
            with open("header_vulnerability_report.json", "w", encoding="utf-8") as f:
                json.dump(self.last_report, f, indent=2)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CrawlerApp()
    window.show()
    sys.exit(app.exec())