"""INVENTED EML, addresses, receiver profile and links on example.eg/example.com only."""
from email.message import EmailMessage
import json
import socket

import pytest

from app.engines.email_headers import ReceiverProfile
from app.services import eml_reader
from app.services.mail_import import DISABLED, import_eml
from provider_fixtures import write_invented_registry

PROFILE = ReceiverProfile('invented', 'receiver.example.eg', ('received-spf', 'authentication-results'),
                          'https://example.eg/invented-spec', '2026-11-26', 'invented-reviewer')


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('unexpected network access')
    for name in ('socket', 'getaddrinfo', 'create_connection'):
        monkeypatch.setattr(socket, name, forbidden)


def invented(tmp_path, headers='', body='Invented content.', author='Tester <sender@example.eg>', **args):
    path = tmp_path / 'invented-private.eml'
    path.write_bytes((headers + 'From: ' + author + '\nSubject: invented-private\n\n' + body).encode())
    return import_eml(path, **args)


@pytest.mark.parametrize('auth,spf,attested,reason', [
    ('spf=fail smtp.mailfrom=x@example.eg; dkim=fail', 'fail', True, 'email_provider_auth_failure_reported'),
    ('dmarc=fail; dkim=pass', 'fail', True, 'email_provider_auth_failure_reported'),
    ('spf=fail; dkim=pass', 'fail', True, None),
    ('spf=softfail; dkim=temperror', 'softfail', True, None),
    ('spf=fail smtp.mailfrom=x@example.eg', 'pass', True, 'email_auth_report_conflict'),
    ('spf=fail', 'fail', False, 'email_auth_report_untrusted'),
    ('spf=madeup', 'fail', True, 'email_auth_not_visible'),
])
def test_invented_report_gates(tmp_path, auth, spf, attested, reason):
    headers = f'Received-SPF: {spf} envelope-from=x@example.eg\nAuthentication-Results: receiver.example.eg; {auth}\n'
    review = invented(tmp_path, headers, profile=PROFILE, attested=attested)
    assert [f.evidence.reasons[0] for f in review.findings] == ([reason] if reason else [])
    assert all(f.severity in ('low', 'info') and not f.attack for f in review.findings)


def test_duplicate_wrong_boundary_and_arc_do_not_establish_trust(tmp_path):
    line = 'Authentication-Results: receiver.example.eg; dmarc=fail\n'
    for headers, code in [(line, 'email_auth_report_untrusted'),
                          ('Received-SPF: pass\n' + line + line, 'email_auth_report_conflict')]:
        review = invented(tmp_path, headers + 'ARC-Seal: i=1; cv=pass\n', profile=PROFILE, attested=True)
        assert code in review.coverage and review.reported['arc'] == 'reported_arc_incomplete'
        assert all(f.severity == 'info' for f in review.findings)


def test_domain_comparison_and_forwarding_controls(tmp_path):
    review = invented(tmp_path, 'Reply-To: a@reply.example.eg\nReturn-Path: <b@bounce.example.eg>\n')
    assert {f.evidence.reasons[0] for f in review.findings if f.severity == 'low'} == {
        'email_reply_to_domain_differs', 'email_return_path_domain_differs'}
    for headers in ('Reply-To: other@example.eg\nReturn-Path: <>\n',
                    'From: second@example.com\nReply-To: a@reply.example.eg\n'):
        assert all(f.severity == 'info' for f in invented(tmp_path, headers).findings)


def test_display_claim_requires_action_and_independent_proof(tmp_path):
    snap = write_invented_registry(tmp_path)
    headers = 'Received-SPF: none\nAuthentication-Results: receiver.example.eg; dkim=fail\n'
    opts = dict(author='Invented Example Bank <sender@other.example.eg>', snapshot=snap, profile=PROFILE)
    for attested, expected in ((False, 'medium'), (True, 'high')):
        review = invented(tmp_path, headers, 'Pay the invoice', **opts, attested=attested)
        claim, = [f for f in review.findings if f.kind == 'email_provider_impersonation']
        assert claim.severity == expected and claim.attack[0].basis == 'email_provider_identity_conflict'
    assert not any(f.attack for f in invented(tmp_path, headers, '> Pay the invoice', **opts).findings)


def test_mime_inert_links_boundaries_and_privacy(tmp_path):
    msg = EmailMessage()
    msg['From'] = 'Private Name <sender@example.eg>'
    msg['Message-ID'] = '<invented-private@example.eg>'
    msg.set_content('Invented: https://example.eg/A')
    msg.add_alternative('<a href="https://example.eg/A">https://example.com</a>'
                        '<img src="https://image.example.eg"><a href="data:private">x</a>', subtype='html')
    msg.add_attachment(b'https://attachment.example.eg', maintype='application', subtype='octet-stream', filename='private')
    path = tmp_path / 'private.eml'
    path.write_bytes(msg.as_bytes())
    seen = []
    def score(raw):
        seen.append(raw)
        return {'probability': 0.5, 'threshold': 0.5, 'version': 'invented'}
    report = import_eml(path, scorer=score)
    assert seen == ['https://example.eg/A']
    assert {'email_attachment_skipped', 'email_link_scheme_unsupported', 'email_anchor_host_differs'} <= report.coverage
    link, = [f for f in report.findings if f.kind == 'email_link_model_observation']
    assert link.severity == 'low' and link.indicators[0].value is None and not link.attack
    blob = json.dumps(report.public())
    assert DISABLED in blob
    assert all(marker not in blob for marker in ('example.eg', 'private', 'Private Name', str(path)))
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize('budget', ['MAX_BYTES', 'MAX_PARTS', 'MAX_DEPTH', 'MAX_HEADER_BYTES',
                                    'MAX_HEADER_LINES', 'MAX_TOKENS', 'MAX_BODY_CHARS', 'MAX_LINKS'])
def test_limits_fail_whole_import_before_scoring(tmp_path, monkeypatch, budget):
    monkeypatch.setattr(eml_reader, budget, 0)
    msg = EmailMessage()
    msg['From'] = 'tester@example.eg'
    msg.set_content('Invented https://example.eg/check')
    msg.add_alternative('<a href="https://example.eg/">invented</a>', subtype='html')
    path = tmp_path / 'invented.eml'
    path.write_bytes(msg.as_bytes())
    with pytest.raises(eml_reader.ImportErrorCode, match='^email_import_limit_exceeded$'):
        import_eml(path, scorer=lambda raw: pytest.fail('scored partial input'))


def test_real_scorer_and_unavailable_state(tmp_path):
    from app.engines.url_model import score_url
    url = 'https://example.eg/invented'
    actual = score_url(url)
    result = invented(tmp_path, body=url)
    assert actual is not None
    assert any(f.kind == 'email_link_model_observation' for f in result.findings) == (
        actual['probability'] >= actual['threshold'])
    assert 'email_url_model_unavailable' in invented(tmp_path, body=url, scorer=lambda u: None).coverage
