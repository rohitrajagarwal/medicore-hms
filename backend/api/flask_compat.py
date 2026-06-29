"""
MediCore Flask Compatibility API
SECURITY TRAINING — p/flask Semgrep rules apply here
"""
from flask import Flask, request, render_template_string, redirect, send_file, make_response
import os, subprocess, sqlite3
from markupsafe import Markup

app = Flask(__name__)


@app.route('/api/v2/patients/search')
def flask_patient_search():
    name = request.args.get('name', '')
    # Semgrep p/flask SQL injection
    conn = sqlite3.connect('/var/medicore/medicore.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM patients WHERE name='" + name + "'")  # Semgrep fires
    return str(cursor.fetchall())


@app.route('/api/v2/render')
def flask_render():
    tmpl = request.args.get('template', '')
    # Semgrep p/flask SSTI: render_template_string with user input
    return render_template_string(tmpl)  # Semgrep fires on this


@app.route('/api/v2/redirect')
def flask_redirect():
    url = request.args.get('next', '/')
    return redirect(url)  # Semgrep open redirect


@app.route('/api/v2/file')
def flask_send_file():
    filename = request.args.get('file', '')
    return send_file('/var/medicore/docs/' + filename)  # path traversal


@app.route('/api/v2/exec', methods=['POST'])
def flask_exec():
    cmd = request.form.get('cmd', '')
    result = subprocess.check_output(cmd, shell=True)  # B602
    return make_response(result, 200)


@app.route('/api/v2/xss')
def flask_xss():
    name = request.args.get('name', '')
    return make_response(Markup('<h1>' + name + '</h1>'))  # XSS


@app.route('/api/v2/ssrf', methods=['POST'])
def flask_ssrf():
    import requests as req_lib
    url = request.form.get('url', '')
    resp = req_lib.get(url)  # SSRF
    return resp.text
