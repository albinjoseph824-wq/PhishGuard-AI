from flask import Flask, render_template, request, jsonify
from detector import analyze_url

app = Flask(__name__)

@app.get("/")
def home():
    return render_template("index.html")

@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    return jsonify(analyze_url((data.get("url") or "").strip()))

if __name__ == "__main__":
    app.run(debug=True)
