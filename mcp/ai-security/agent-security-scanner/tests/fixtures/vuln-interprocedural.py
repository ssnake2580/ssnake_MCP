from flask import Flask, request
import os

app = Flask(__name__)

def process_input(data):
    return "cmd: " + data

@app.route('/indirect')
def indirect_injection():
    cmd = request.args.get('cmd')
    processed = process_input(cmd)
    os.system(processed)
    return "OK"
