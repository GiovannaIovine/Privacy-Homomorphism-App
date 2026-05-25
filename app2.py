from flask import Flask, render_template, request
import uuid
import os

app = Flask(__name__)

OUTPUT_FOLDER = "outputs"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


@app.route("/")
def home():
    return render_template("Index2.html")


def safe_mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if len(values) > 0 else 0


@app.route("/upload", methods=["POST"])
def upload():

    file = request.files["file"]

    lines = file.read().decode("utf-8").strip().split("\n")

    header = lines[0].split(",")
    data_lines = lines[1:]

    columns = [[] for _ in header]
    print("HEADER:", len(header))
    
    for line in data_lines:

        parts = line.split(",")
        print("PARTS:", len(parts))

        for i, value in enumerate(parts):

            try:
                if value != "":
                    columns[i].append(int(value))
                else:
                    columns[i].append(None)
            except:
                columns[i].append(None)

    means = [safe_mean(col) for col in columns]

    

    # output CSV
    file_id = str(uuid.uuid4())
    out_file = os.path.join(OUTPUT_FOLDER, f"{file_id}_avg.csv")

    with open(out_file, "w") as f:
        f.write(",".join(header) + "\n")
        f.write(",".join(map(str, means)) + "\n")

    # HTML 
    table_html = "<table><tr>"
    table_html += "".join(f"<th>{h}</th>" for h in header)
    table_html += "</tr><tr>"
    table_html += "".join(f"<td>{m}</td>" for m in means)
    table_html += "</tr></table>"

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
            .container {{
                max-width: 800px;
                margin: auto;
                background: white;
                padding: 30px;
                border-radius: 12px;
            }}
            table {{
                width: 100%;
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

            <a class="button" href="/download/{file_id}">
                Download CSV
            </a>

            <br><br>
            <a href="/">Upload another file</a>

        </div>
    </body>
    </html>
    """


@app.route("/download/<file_id>")
def download(file_id):
    path = os.path.join(OUTPUT_FOLDER, f"{file_id}_avg.csv")
    return open(path, "rb").read(), 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=column_averages.csv"
    }


if __name__ == "__main__":
    app.run(debug=True)