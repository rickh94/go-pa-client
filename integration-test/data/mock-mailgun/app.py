# noinspection PyUnresolvedReferences
import json

from flask import Flask, request

app = Flask(__name__)


@app.route("/v3/mg.example.com/messages", methods=("GET", "POST"))
def endpoint():
    if (
        not request.authorization["username"] == "api"
        or not request.authorization["password"] == "fake-mailgun-key"
    ):
        return "Unauthorized", 401
    to = request.form.get("to")
    with open(f"/test-data/email-to-{to}.json", "w") as outfile:
        json.dump(request.form, outfile)
    return "success"
