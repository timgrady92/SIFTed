"""Application-scoped access to shared configuration and persistence."""
from flask import current_app
from .storage import Repository


def runtime_repository():
    with current_app.extensions["repository_lock"]:
        if "repository" not in current_app.extensions:
            current_app.extensions["repository"] = Repository(current_app.config["DATABASE_PATH"])
        return current_app.extensions["repository"]


def runtime_settings():
    return current_app.config["SETTINGS"]
