#!/usr/bin/env python3

from flask import Flask, request, session
from flask_migrate import Migrate
from flask_restful import Api, Resource
from werkzeug.exceptions import NotFound, Unauthorized
from models import db, User, Recipe
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'super-secret-key'

db.init_app(app)
migrate = Migrate(app, db)
api = Api(app)


# ---------- Helpers ----------
def current_user():
    if "user_id" in session:
        return User.query.get(session["user_id"])
    return None


# ---------- Resources ----------
class Signup(Resource):
    def post(self):
        data = request.get_json()

        if not data.get("username") or not data.get("password"):
            return {"errors": ["validation errors"]}, 422
        try:
            user = User(
                username=data["username"],
                bio=data.get("bio"),
                image_url=data.get("image_url"),
            )
            user.password_hash = data["password"]
            db.session.add(user)
            db.session.commit()

            session["user_id"] = user.id
            return user.to_dict(), 201

        except IntegrityError:
            db.session.rollback()
            return {"errors": ["Username must be unique"]}, 422


class CheckSession(Resource):
    def get(self):
        user = current_user()
        if user:
            return user.to_dict(), 200
        return {"error": "Unauthorized"}, 401


class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get("username")).first()

        if user and user.authenticate(data.get("password")):
            session["user_id"] = user.id
            return user.to_dict(), 200

        return {"error": "Invalid username or password"}, 401


class Logout(Resource):
    def delete(self):
        if not current_user():
            return {"error": "Unauthorized"}, 401

        session.pop("user_id", None)
        return {}, 204


class RecipeIndex(Resource):
    def get(self):
        user = current_user()
        if not user:
            return {"error": "Unauthorized"}, 401

        recipes = [r.to_dict() for r in Recipe.query.all()]
        return recipes, 200

    def post(self):
        user = current_user()
        if not user:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        errors = []

        # Validation rules
        if not data.get("title"):
            errors.append("Title is required")
        if not data.get("instructions") or len(data.get("instructions")) < 50:
            errors.append("Instructions must be at least 50 characters long")
        if not data.get("minutes_to_complete") or not isinstance(
            data.get("minutes_to_complete"), int
        ):
            errors.append("Minutes to complete must be a number")

        if errors:
            return {"errors": errors}, 422

        try:
            recipe = Recipe(
                title=data["title"],
                instructions=data["instructions"],
                minutes_to_complete=data["minutes_to_complete"],
                user_id=user.id,
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201

        except Exception:
            db.session.rollback()
            return {"errors": ["Unable to create recipe"]}, 422


# ---------- Routes ----------
api.add_resource(Signup, "/signup")
api.add_resource(CheckSession, "/check_session")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")
api.add_resource(RecipeIndex, "/recipes")


# ---------- Error Handling ----------
@app.errorhandler(NotFound)
def handle_not_found(e):
    return {"error": "Not found"}, 404


if __name__ == "__main__":
    app.run(port=5555, debug=True)

