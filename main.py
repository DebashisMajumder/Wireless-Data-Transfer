from flask import Flask, render_template, redirect, url_for, request, send_from_directory, jsonify
import os
from werkzeug.utils import secure_filename

app = Flask (__name__)

UPLOAD_FOLDER = '/home/debashis/server/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    files = os.listdir(UPLOAD_FOLDER)
    return render_template('index.html', files = files)


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "No file", 400

    file = request.files["file"]
    if file.filename == "":
        return "Empty filename", 400

    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return ("", 204)

@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename,
        as_attachment=True
    )

@app.route("/delete/<filename>", methods=["POST"])
def delete_file(filename):
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(path):
        os.remove(path)
    return redirect(url_for("index"))

@app.route("/stats")
def stats():
    st = os.statvfs(app.config["UPLOAD_FOLDER"])
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = total - free
    return jsonify({"total": total, "used": used})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
    
