"""Setup guidance uses native installation paths without privileged app actions."""
import html
import re
import shlex
import subprocess

from app import create_app
from sifted_core import web
from sifted_core.tool_base import ValidationError


def test_symbol_guide_quotes_discovered_paths_and_defers_optional_setup(tmp_path, monkeypatch):
    root = str(tmp_path / "Volatility's symbols $(touch unsafe)")
    monkeypatch.setattr(web, 'discover_volatility', lambda settings: {'symbol_paths': [root]})
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path / 'case.db')})
    response = app.test_client().get('/guides/volatility-symbols')
    assert response.status_code == 200
    text = response.get_data(as_text=True)
    commands = [html.unescape(command) for command in re.findall(r'<pre class="command">(.*?)</pre>', text, re.S)]
    install = next(code for code in commands if 'sudo cp ' in code)
    assert shlex.quote(root) in install
    assert 'sudo vol' not in text and 'chmod 777' not in text
    for code in commands:
        result = subprocess.run(['bash', '-n'], input=code, text=True, capture_output=True)
        assert result.returncode == 0, result.stderr
    assert text.count('<details class="card block">') == 3
    assert 'volatility3-test-data/releases/download/v0.0.1/windows.zip' in text
    assert 'sha256sum --check --ignore-missing SHA256SUMS' in text


def test_guide_stays_available_without_volatility(tmp_path, monkeypatch):
    def missing(settings):
        raise ValidationError('Volatility is not installed.')
    monkeypatch.setattr(web, 'discover_volatility', missing)
    app = create_app({'TESTING': True, 'SIFTED_DATABASE_PATH': str(tmp_path / 'case.db')})
    response = app.test_client().get('/guides/volatility-symbols')
    assert response.status_code == 200
    assert b'Volatility is not installed.' in response.data
    assert b'volatility3-test-data/releases/download' in response.data
    assert b'sudo cp' not in response.data
