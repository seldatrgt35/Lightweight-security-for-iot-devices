from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/data", methods=["POST"])
def data():
    print(request.json)
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
