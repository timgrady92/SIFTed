"""Flask application factory and local launcher."""
import logging
import threading
from flask import Flask
from sifted_core.api import create_blueprint
from sifted_core.config import load_config
from sifted_core.context import runtime_repository, runtime_settings
from sifted_core.web import web


def create_app(config=None):
    application = Flask(__name__)
    application.config.update(load_config(config))
    application.extensions["repository_lock"] = threading.Lock()
    application.register_blueprint(web)
    application.register_blueprint(create_blueprint(runtime_repository, runtime_settings))
    return application


app = create_app()

if __name__ == "__main__":
    from sifted_core.launcher import run
    logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s %(name)s %(message)s")
    run(app)
