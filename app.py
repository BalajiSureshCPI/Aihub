from flask import Flask, render_template, request, jsonify
from detector import analyze_message

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.post('/api/analyze')
def analyze():
    data = request.get_json(silent=True) or {}
    text = (data.get('text') or '').strip()
    input_type = data.get('input_type', 'auto')
    if not text:
        return jsonify({'error': 'Please enter a message, email, SMS, WhatsApp text, or URL.'}), 400
    return jsonify(analyze_message(text, input_type))

if __name__ == '__main__':
    app.run(debug=True)
