from flask import Flask, render_template, request
import os
from analyzer import PDFAnalyzer

app = Flask(__name__)

# Folder to store uploaded PDFs
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# -------------------------------
# Home Page
# -------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------
# Analyze PDF
# -------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():

    if "pdf" not in request.files:
        return "No file uploaded."

    pdf = request.files["pdf"]

    if pdf.filename == "":
        return "Please select a PDF."

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], pdf.filename)

    pdf.save(filepath)

    analyzer = PDFAnalyzer(filepath)

    analyzer.extract_metadata()
    analyzer.scan_keywords()
    analyzer.extract_iocs()
    analyzer.risk_score()

    md5, sha256 = analyzer.get_hash()

    # Decide severity
    if analyzer.score >= 75:
        severity = "Critical"

    elif analyzer.score >= 50:
        severity = "High"

    elif analyzer.score >= 25:
        severity = "Medium"

    else:
        severity = "Low"

    return render_template(

        "result.html",

        filename=pdf.filename,

        metadata=analyzer.metadata,

        keywords=analyzer.keywords_found,

        urls=analyzer.urls,

        ips=analyzer.ips,

        score=analyzer.score,

        severity=severity,

        md5=md5,

        sha256=sha256

    )


# -------------------------------
# Run Server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)