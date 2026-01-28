from flask import Flask, request, jsonify
from phishing_detector import PhishingScanner
import logging
import traceback

app = Flask(__name__)


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/scan', methods=['POST'])
def scan_email():
    try:
        data = request.get_json(force=True, silent=True)
        if not data:
            return jsonify({"is_phishing": False, "threats": ["Error: No data"]}), 400

        email_text = data.get('text', '')
        
        scanner = PhishingScanner()
        threats = scanner.run_scan(email_text)
        
        # --- Risk Score Calculation ---
        score = 0
        for t in threats:
            if "Suspicious Link" in t: 
                score += 40
            elif "Spoofing" in t:
                score += 50
            elif "Urgency" in t:
                score += 10
            else:
                score += 10
        
        if score > 100: score = 100

        return jsonify({
            "is_phishing": len(threats) > 0,
            "threats": threats,
            "risk_score": score
        })

    except Exception as e:
        logger.error(traceback.format_exc())
        return jsonify({
            "is_phishing": False, 
            "threats": [f"Server Error: {str(e)}"]
        }), 200

if __name__ == '__main__':
    app.run(port=5000)