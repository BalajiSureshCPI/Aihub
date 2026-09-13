# SentinelAI — AI Scam Detection Platform

Educational final-year project for detecting scam/phishing SMS, WhatsApp messages, emails and URLs.

## Stack
- Python + Flask
- NLP/rule-based explainable scoring
- URL feature analysis
- Optional TF-IDF + Logistic Regression ML pipeline
- HTML/CSS/JavaScript

## Run
```bash
python -m venv .venv
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Project flow
Browser → Flask API → text preprocessing → NLP + URL features → risk score → explanations.

## Future upgrades
Train on a balanced phishing dataset, add SHAP/LIME, multilingual Tamil/Hindi support, URL reputation APIs, analytics dashboard, authentication and production deployment.

> Prototype only: an automated score is not proof that a message is safe.
