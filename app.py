"""Flask application factory."""
import threading
from flask import Flask
from sifted_core.api import create_blueprint
from sifted_core.config import load_config
from sifted_core.context import runtime_repository, runtime_settings
from sifted_core.web import web
from sifted_core.evidence_web import evidence


def create_app(config=None):
    application = Flask(__name__)
    application.config.update(load_config(config))
    application.extensions["repository_lock"] = threading.Lock()
    application.register_blueprint(web)
    application.register_blueprint(evidence)
    application.register_blueprint(create_blueprint(runtime_repository, runtime_settings))
    return application


app = create_app()
