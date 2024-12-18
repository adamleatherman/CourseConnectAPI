# Standard library imports
import io
import json
import os
from urllib.request import urlopen

# Third-party library imports
import requests
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_file
from jose import jwt

# Google Cloud imports
from google.cloud import datastore, storage

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY")

APP_URL = "https://leathead-a6.uc.r.appspot.com"
CLIENT_ID = "AvzddxmHgian3U6lNz2wjoInAaRTm9hD"
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN = "dev-fp2p7cq7try46bew.us.auth0.com"
ALGORITHMS = ["RS256"]
PHOTO_BUCKET = "leathead-a6.appspot.com"

oauth = OAuth(app)
auth0 = oauth.register(
    "auth0",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        "scope": "openid profile email",
    },
)

client = datastore.Client()
storage_client = storage.Client()


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    if "Authorization" in request.headers:
        auth_header = request.headers["Authorization"].split()
        token = auth_header[1]
    else:
        raise AuthError(
            {
                "code": "no auth header",
                "description": "Authorization header is missing",
            },
            401,
        )

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. "
                "Use an RS256 signed JWT Access Token",
            },
            401,
        )
    if unverified_header["alg"] == "HS256":
        raise AuthError(
            {
                "code": "invalid_header",
                "description": "Invalid header. "
                "Use an RS256 signed JWT Access Token",
            },
            401,
        )
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/",
            )
        except jwt.ExpiredSignatureError:
            raise AuthError(
                {"code": "token_expired", "description": "token is expired"},
                401,
            )
        except jwt.JWTClaimsError:
            raise AuthError(
                {
                    "code": "invalid_claims",
                    "description": "incorrect claims,"
                    " please check the audience and issuer",
                },
                401,
            )
        except Exception:
            raise AuthError(
                {
                    "code": "invalid_header",
                    "description": "Unable to parse authentication" " token.",
                },
                401,
            )

        return payload
    else:
        raise AuthError(
            {"code": "no_rsa_key", "description": "No RSA key in JWKS"}, 401
        )


@app.route("/decode", methods=["GET"])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route("/")
def index():
    return "Please navigate to /courses or /users to use this API"


@app.route("/users/login", methods=["POST"])
def login_user():
    content = request.get_json()
    try:
        username = content["username"]
        password = content["password"]
    except KeyError:
        return {"Error": "The request body is invalid"}, 400
    body = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = {"content-type": "application/json"}
    url = "https://" + DOMAIN + "/oauth/token"
    r = requests.post(url, json=body, headers=headers)
    response_data = r.json()
    token = response_data.get("id_token")
    if not token:
        return {"Error": "Unauthorized"}, 401
    return {"token": token}, 200, {"Content-Type": "application/json"}


def get_admin_sub():
    query = client.query(kind="users")
    query.add_filter("role", "=", "admin")
    results = list(query.fetch())
    admin_user = results[0]
    admin_sub_value = admin_user.get("sub")
    return admin_sub_value


@app.route("/users", methods=["GET"])
def get_users():
    admin_sub_value = get_admin_sub()
    try:
        payload = verify_jwt(request)
        requestor = payload["sub"]
        if requestor != admin_sub_value:
            return {"Error": "You don't have permission on this resource"}, 403
        query = client.query(kind="users")
        users = list(query.fetch())
        for u in users:
            u["id"] = u.key.id
        return users, 200
    except AuthError:
        return {"Error": "Unauthorized"}, 401


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401
    user = client.get(key=client.key("users", user_id))
    if user is None:
        return {"Error": "You don't have permission on this resource"}, 403
    requestor_sub = payload["sub"]
    if requestor_sub != user["sub"] and requestor_sub != get_admin_sub():
        return {"Error": "You don't have permission on this resource"}, 403
    response = {"id": user.key.id, "role": user["role"], "sub": user["sub"]}
    if requestor_sub == get_admin_sub():
        return response, 200
    if "avatar" in user:
        response["avatar_url"] = APP_URL + f"/users/{user_id}/avatar"
    response["courses"] = []
    if user["role"] == "student":
        courses = []
        query = client.query(kind="enrollments")
        results = list(query.fetch())
        for c in results:
            if user.key.id == c["students"]:
                courses.append(c.key.id)
        for c in courses:
            response["courses"].append(c)
    elif user["role"] == "instructor":
        courses = []
        query = client.query(kind="courses")
        results = list(query.fetch())
        for c in results:
            if user.key.id == c["instructor_id"]:
                courses.append(c.key.id)
        for c in courses:
            response["courses"].append(c)
    return response, 200


@app.route("/users/<int:user_id>/avatar", methods=["POST"])
def avatar_post(user_id):
    if "file" not in request.files:
        return {"Error": "The request body is invalid"}, 400
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401
    requestor_sub = payload["sub"]
    user = client.get(key=client.key("users", user_id))
    if requestor_sub != user["sub"]:
        return {"Error": "You don't have permission on this resource"}, 403
    file_obj = request.files["file"]
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    try:
        blob.upload_from_file(file_obj)
    except Exception as e:
        return {"Error": f"File upload failed: {str(e)}"}, 500
    user.update({"avatar": file_obj.filename})
    client.put(user)
    return {"avatar_url": APP_URL + f"/users/{user_id}/avatar"}, 200


@app.route("/users/<int:user_id>/avatar", methods=["GET"])
def avatar_get(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401
    requestor_sub = payload["sub"]
    user = client.get(key=client.key("users", user_id))
    print(user["sub"])
    print(requestor_sub)
    if requestor_sub != user["sub"]:
        return {"Error": "You don't have permission on this resource"}, 403
    if "avatar" not in user:
        return {"Error": "Not found"}, 404
    file_name = user["avatar"]
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    return (
        send_file(file_obj, mimetype="image/x-png", download_name=file_name),
        200,
    )


@app.route("/users/<int:user_id>/avatar", methods=["DELETE"])
def avatar_delete(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError:
        return {"Error": "Unauthorized"}, 401
    requestor_sub = payload["sub"]
    user = client.get(key=client.key("users", user_id))
    if requestor_sub != user["sub"]:
        return {"Error": "You don't have permission on this resource"}, 403
    if "avatar" not in user:
        return {"Error": "Not found"}, 404
    file_name = user["avatar"]
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    blob = bucket.blob(file_name)
    blob.delete()
    del user["avatar"]
    client.put(user)
    return "", 204


@app.route("/courses", methods=["POST"])
def courses_post():
    if request.method == "POST":
        content = request.get_json()

        try:
            payload = verify_jwt(request)
        except AuthError:
            return {"Error": "Unauthorized"}, 401

        required_fields = [
            "subject",
            "number",
            "title",
            "term",
            "instructor_id",
        ]
        missing_fields = [
            field for field in required_fields if field not in content
        ]
        if missing_fields:
            return {"Error": "The request body is invalid"}, 400

        admin_sub_value = admin_sub_value = get_admin_sub()
        if payload["sub"] != admin_sub_value:
            return {"Error": "You don't have permission on this resource"}, 403

        query = client.query(kind="users")
        query.add_filter("role", "=", "instructor")
        results = list(query.fetch())
        instructor_ids = [r.key.id for r in results]
        if content["instructor_id"] not in instructor_ids:
            return {"Error": "The request body is invalid"}, 400

        new_course = datastore.entity.Entity(key=client.key("courses"))
        new_course.update(
            {
                "subject": content["subject"],
                "number": content["number"],
                "title": content["title"],
                "term": content["term"],
                "instructor_id": content["instructor_id"],
            }
        )
        client.put(new_course)
        new_course["id"] = new_course.key.id
        new_course["self"] = APP_URL + "/courses" + f"/{new_course["id"]}"

        new_enrollment = datastore.entity.Entity(key=client.key("enrollments"))
        new_enrollment.update({"course_id": new_course.key.id, "students": []})
        client.put(new_enrollment)
        return new_course, 201
    else:
        return jsonify(error="Method not recogonized")


@app.route("/courses", methods=["GET"])
def get_courses():
    offset = request.args.get("offset", default=0, type=int)
    limit = request.args.get("limit", default=3, type=int)
    query = client.query(kind="courses")
    query.order = ["subject"]
    query_iter = query.fetch(offset=offset, limit=limit)
    courses = list(query_iter)

    results = {
        "courses": [],
        "next": APP_URL + f"/courses?limit=3&offset={offset + 3}",
    }

    for c in courses:
        course = {
            "id": c.key.id,
            "instructor_id": c["instructor_id"],
            "number": c["number"],
            "self": APP_URL + f"/courses/{c.key.id}",
            "subject": c["subject"],
            "term": c["term"],
            "title": c["title"],
        }
        results["courses"].append(course)

    return results, 200


@app.route("/courses" + "/<int:id>", methods=["GET"])
def get_course(id):
    key = client.key("courses", id)
    course = client.get(key=key)

    if not course:
        return {"Error": "Not found"}, 404

    course["id"] = course.key.id
    course["self"] = APP_URL + "/courses" + f"/{course["id"]}"

    return course, 200


def delete_enrollment(course_id):
    query = client.query(kind="enrollments")
    query.add_filter("course_id", "=", course_id)
    enrollments = list(query.fetch())

    for enrollment in enrollments:
        client.delete(enrollment.key)


@app.route("/courses" + "/<int:id>", methods=["DELETE"])
def delete_course(id):
    try:
        payload = verify_jwt(request)
        key = client.key("courses", id)
        course = client.get(key=key)

        admin_sub_value = get_admin_sub()

        if payload["sub"] != admin_sub_value:
            return {"Error": "You don't have permission on this resource"}, 403

        if not course:
            return {"Error": "You don't have permission on this resource"}, 403

        client.delete(key)
        delete_enrollment(id)

        return "", 204

    except AuthError:
        return {"Error": "Unauthorized"}, 401


def validate_user_ids(user_ids):
    invalid_users = []
    non_students = []

    for user_id in user_ids:
        key = client.key("users", user_id)
        user = client.get(key)
        if not user:
            invalid_users.append(user_id)
        elif user.get("role") != "student":
            non_students.append(user_id)

    return invalid_users, non_students


@app.route("/courses/<int:course_id>/students", methods=["PATCH"])
def update_enrollment(course_id):
    try:
        payload = verify_jwt(request)
        requestor_sub = payload["sub"]

        admin_sub_value = get_admin_sub()

        key = client.key("courses", course_id)
        course = client.get(key=key)
        course_instructor_id = course["instructor_id"]
        key = client.key("users", course_instructor_id)
        instructor = client.get(key=key)
        if not course:
            return {"Error": "You don't have permission on this resource"}, 403

        if (
            instructor["sub"] != requestor_sub
            and admin_sub_value != requestor_sub
        ):
            return {"Error": "You don't have permission on this resource"}, 403

        body = request.get_json()
        add_list = set(body.get("add", []))
        remove_list = set(body.get("remove", []))
        conflicts = set(add_list).intersection(remove_list)
        if conflicts:
            return {"Error": "Enrollment data is invalid"}, 409

        all_user_ids = set(add_list | remove_list)
        invalid_users, non_students = validate_user_ids(all_user_ids)

        if invalid_users or non_students:
            return {"Error": "Enrollment data is invalid"}, 409

        query = client.query(kind="enrollments")
        query.add_filter("course_id", "=", course_id)
        results = list(query.fetch())
        enrollment = results[0]

        for student in add_list:
            if student not in enrollment["students"]:
                enrollment["students"].append(student)
        for student in remove_list:
            if student in enrollment["students"]:
                enrollment["students"].remove(student)

        client.put(enrollment)

        return "", 200
    except AuthError:
        return {"Error": "Unauthorized"}, 401


@app.route("/courses/<int:course_id>/students", methods=["GET"])
def get_enrollment(course_id):
    try:
        payload = verify_jwt(request)
        requestor_sub = payload["sub"]

        admin_sub_value = get_admin_sub()

        key = client.key("courses", course_id)
        course = client.get(key=key)
        course_instructor_id = course["instructor_id"]
        key = client.key("users", course_instructor_id)
        instructor = client.get(key=key)

        if not course:
            return {"Error": "You don't have permission on this resource"}, 403

        if (
            instructor["sub"] != requestor_sub
            and admin_sub_value != requestor_sub
        ):
            return {"Error": "You don't have permission on this resource"}, 403

        query = client.query(kind="enrollments")
        query.add_filter("course_id", "=", course_id)
        results = list(query.fetch())
        enrollment = results[0]

        return enrollment["students"], 200

    except AuthError:
        return {"Error": "Unauthorized"}, 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)
