from flask import Flask, render_template, request
import os
from werkzeug.utils import secure_filename
import pandas as pd
from step2_server_sum import *

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "outputs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

@app.route("/")
def home():
    return render_template("Index2.html")


@app.route("/upload", methods=["POST"])
def upload():

    csv_file = request.files["file"]
    json_file = request.files["metadata"]

    csv_name = secure_filename(csv_file.filename)
    json_name = secure_filename(json_file.filename)

    csv_path = os.path.join(UPLOAD_FOLDER, csv_name)
    json_path = os.path.join(UPLOAD_FOLDER, json_name)

    csv_file.save(csv_path)
    json_file.save(json_path)
    # output file generato dalla tua funzione
    output_file = os.path.join(OUTPUT_FOLDER, "encrypted_sums.csv")

    # 1. chiami la tua funzione
    server_sum(csv_path, json_path, output_file)
    
    # 2. leggi CSV output
    df = pd.read_csv(output_file)

    def parse_column(cell):
        data = json.loads(cell)  # converte stringa -> lista JSON
        return [float(x[1]) for x in data]  # prende seconda colonna
    
    columns = df.columns.tolist()
    parsed = {}

    for col in columns:
        parsed[col] = parse_column(df[col].iloc[0])

    num_rows = len(parsed[columns[0]])

    means = [sum(parsed[col]) / num_rows for col in columns]
    header = columns
    
    # 5. costruzione tabella HTML
    table_html = "<table><tr>"
    table_html += "".join(f"<th>{h}</th>" for h in header)
    table_html += "</tr><tr>"
    table_html += "".join(f"<td>{m}</td>" for m in means)
    table_html += "</tr></table>"

    # 6. pagina HTML finale
    return f"""
    <html>
    <head>
        <title>Results</title>
        <style>
            body {{
                font-family: Arial;
                background: #f3f4f6;
                padding: 40px;
            }}

            table {{
                width: 80%;
                border-collapse: collapse;
                margin-top: 20px;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 10px;
                text-align: center;
            }}
            th {{
                background: #2563eb;
                color: white;
            }}
            a.button {{
                display: inline-block;
                margin-top: 20px;
                padding: 10px 15px;
                background: #2563eb;
                color: white;
                text-decoration: none;
                border-radius: 8px;
            }}
        </style>
    </head>

    <body>
        <div class="container">

            <h1>Column Averages</h1>

            {table_html}

            <br><br>
            <a class="button" href="/download/output.csv">
                Download CSV
            </a>

            <br><br>
            <a href="/">Upload another file</a>

        </div>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)