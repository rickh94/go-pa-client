import json

from flask import Flask, request
import python_jwt as jwt
from jwcrypto.jws import InvalidJWSObject, InvalidJWSSignature

app = Flask(__name__)


@app.route("/magic")
def endpoint():
    token = request.args.get("idToken")
    if not token:
        return "no token", 400
    refresh_token = request.args.get("refreshToken")
    try:
        headers, claims = jwt.process_jwt(token)
    except (
        jwt._JWTError,
        UnicodeDecodeError,
        InvalidJWSObject,
        InvalidJWSSignature,
        ValueError,
    ):
        return "invalid token", 400
    with open(f"/test-data/magic-from-{claims['sub']}.json", "w") as outfile:
        json.dump({"idToken": token, "refreshToken": refresh_token}, outfile)
    return "success"
