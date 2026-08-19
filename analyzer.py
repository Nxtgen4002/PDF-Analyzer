import re
import hashlib
from PyPDF2 import PdfReader

class PDFAnalyzer:

    def __init__(self, filename):
        self.filename = filename
        self.metadata = {}
        self.keywords_found = []
        self.urls = []
        self.ips = []
        self.score = 0

        self.suspicious_keywords = [
            "/JavaScript",
            "/JS",
            "/OpenAction",
            "/Launch",
            "/EmbeddedFile",
            "/URI",
            "/RichMedia"
        ]

    def get_hash(self):
        with open(self.filename, "rb") as f:
            data = f.read()

        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        return md5, sha256

    def extract_metadata(self):
        try:
            reader = PdfReader(self.filename)
            if reader.metadata:
                for k, v in reader.metadata.items():
                    self.metadata[k] = str(v)
        except Exception:
            pass

    def scan_keywords(self):
        with open(self.filename, "rb") as f:
            data = f.read()

        for word in self.suspicious_keywords:
            if word.encode() in data:
                self.keywords_found.append(word)

    def extract_iocs(self):
        with open(self.filename, "rb") as f:
            text = f.read().decode("latin1", errors="ignore")

        self.urls = re.findall(r'https?://[^\\s<>"]+', text)
        self.ips = re.findall(r'\\d+\\.\\d+\\.\\d+\\.\\d+', text)

    def risk_score(self):
        score = 0

        if "/JavaScript" in self.keywords_found:
            score += 25

        if "/JS" in self.keywords_found:
            score += 20

        if "/OpenAction" in self.keywords_found:
            score += 20

        if "/EmbeddedFile" in self.keywords_found:
            score += 30

        if len(self.urls) > 0:
            score += 10

        self.score = score