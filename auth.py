from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from datetime import timedelta

# 👇 si tu módulo principal NO se llama app.py, cambia 'app' por 'application' o 'main'
from app import db
from models import User

bp = Blueprint("auth", __name__, url_prefix="/auth")

@bp.post("/register")
def register():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error":"username/password requeridos"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error":"usuario ya existe"}), 409
    u = User(username=username, password_hash=generate_password_hash(password), role="tester")
    db.session.add(u); db.session.commit()
    return jsonify({"ok": True}), 201

@bp.post("/login")
def login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    u = User.query.filter_by(username=username).first()
    if not u or not check_password_hash(getattr(u,"password_hash",""), password):
        return jsonify({"error":"credenciales inválidas"}), 401
    token = create_access_token(identity={"u": u.username, "r": getattr(u,"role","tester")},
                                expires_delta=timedelta(hours=12))
    return jsonify({"access_token": token})
