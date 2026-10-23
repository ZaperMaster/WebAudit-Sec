import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
import requests

from webaudit.scanner.analyzers import (
	analyze_csp,
	analyze_security_header_values,
	cookie_attribute_names,
)
from webaudit.scanner.crawler import scan_website
from webaudit.scanner.links import same_origin_links
from webaudit.scanner.network import fetch, registrable_domain, set_cookie_headers
from webaudit.scanner.results import add_finding, build_scan_result
from web.server import app


client = TestClient(app)

# Ningún test debe escribir en el historial real del usuario.
_history_dir = tempfile.TemporaryDirectory()
_history_patch = patch("webaudit.history.history_dir", return_value=Path(_history_dir.name))
# Los rastreos de prueba no deben pedir el sitemap real por la red.
_sitemap_patch = patch("webaudit.scanner.crawler.sitemap_links", return_value=[])


def setUpModule():
	_history_patch.start()
	_sitemap_patch.start()


def tearDownModule():
	_sitemap_patch.stop()
	_history_patch.stop()
	_history_dir.cleanup()


class ScannerGuidanceTests(unittest.TestCase):
	def test_brand_logo_is_served_as_a_static_asset(self):
		response = client.get("/static/brand/logo-fuera.png")

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.headers["content-type"], "image/png")
		self.assertTrue(response.content.startswith(b"\x89PNG"))
		page = client.get("/").text
		self.assertIn('src="/static/brand/logo-fuera.png"', page)
		css = client.get("/static/css/styles.css").text
		self.assertIn(".logo-mark", css)

	def test_csp_flags_missing_object_src_and_base_uri(self):
		issues = analyze_csp("default-src 'self'")

		titles = {issue[0] for issue in issues}
		self.assertIn("CSP no bloquea objetos incrustados", titles)
		self.assertIn("CSP no restringe base-uri", titles)

	def test_csp_accepts_recommended_object_and_base_directives(self):
		issues = analyze_csp(
			"default-src 'self'; script-src 'self'; "
			"object-src 'none'; base-uri 'self'"
		)

		self.assertEqual(issues, [])

	def test_findings_include_relevant_owasp_category_and_reference(self):
		findings = []

		add_finding(
			findings,
			"WEB-TLS-PROTOCOL",
			"TLS antiguo",
			"high",
			"TLS 1.0",
			"Usa TLS moderno.",
		)

		self.assertTrue(
			findings[0]["owasp_category"].startswith("A04:2025")
		)
		self.assertTrue(
			findings[0]["owasp_reference"].endswith(
				"Transport_Layer_Security_Cheat_Sheet.html"
			)
		)
		self.assertNotIn("deduction", findings[0])

	def test_scan_result_does_not_include_score_or_grade(self):
		result = build_scan_result("https://example.com", 200, [], [])

		self.assertNotIn("score", result)
		self.assertNotIn("grade", result)
		self.assertNotIn("critical", result["summary"])

	def test_invalid_security_header_values_are_reported(self):
		issues = analyze_security_header_values({
			"x-content-type-options": "sniff",
			"x-frame-options": "allowall",
			"referrer-policy": "unsafe-url",
		})

		headers = {issue[0] for issue in issues}
		self.assertEqual(
			headers,
			{"x-content-type-options", "x-frame-options", "referrer-policy"},
		)

	def test_csp_frame_ancestors_supersedes_invalid_x_frame_options(self):
		issues = analyze_security_header_values(
			{"x-frame-options": "allowall"},
			"default-src 'self'; frame-ancestors 'self'",
		)

		self.assertEqual(issues, [])

	def test_set_cookie_headers_are_kept_separate(self):
		cookies = [
			"session=secret-value; Secure; HttpOnly; SameSite=Lax",
			"analytics=other-secret; SameSite=None",
		]
		response = SimpleNamespace(
			raw=SimpleNamespace(
				headers=SimpleNamespace(getlist=lambda name: cookies)
			),
			headers={},
		)

		result = set_cookie_headers(response)

		self.assertEqual(result, cookies)
		self.assertIn("secure", cookie_attribute_names(result[0]))
		self.assertNotIn("secure", cookie_attribute_names(result[1]))

	def test_same_origin_links_excludes_external_and_duplicate_urls(self):
		html = (
			'<a href="/about">About</a>'
			'<a href="https://example.com/contact#team">Contact</a>'
			'<a href="https://other.example/path">External</a>'
			'<a href="javascript:alert(1)">Script</a>'
			'<a href="/about#section">Duplicate</a>'
		).encode()
		response = SimpleNamespace(
			status_code=200,
			headers={"Content-Type": "text/html; charset=utf-8"},
			encoding="utf-8",
			iter_content=lambda chunk_size: [html],
		)

		links, incomplete = same_origin_links("https://example.com/", response)

		self.assertEqual(
			links,
			[
				"https://example.com/about",
				"https://example.com/contact",
			],
		)
		self.assertFalse(incomplete)

	def test_same_origin_links_reports_link_limit(self):
		html = b'<a href="/one">one</a><a href="/two">two</a>'
		response = SimpleNamespace(
			status_code=200,
			headers={"Content-Type": "text/html"},
			encoding="utf-8",
			iter_content=lambda chunk_size: [html],
		)

		with patch("webaudit.scanner.config.MAX_LINKS_PER_PAGE", 1):
			links, incomplete = same_origin_links("https://example.com/", response)

		self.assertEqual(links, ["https://example.com/one"])
		self.assertTrue(incomplete)

	def test_subdomains_are_opt_in_and_stay_under_starting_host(self):
		html = (
			'<a href="https://expired.badssl.com/">Expired</a>'
			'<a href="https://badssl.com/about">Same host</a>'
			'<a href="https://notbadssl.com/">Lookalike</a>'
			'<a href="https://example.org/">External</a>'
		).encode()
		response = SimpleNamespace(
			status_code=200,
			headers={"Content-Type": "text/html"},
			encoding="utf-8",
			iter_content=lambda chunk_size: [html],
		)

		default_links, _ = same_origin_links(
			"https://badssl.com/",
			response,
			scope_host="badssl.com",
		)
		wide_links, _ = same_origin_links(
			"https://badssl.com/",
			response,
			scope_host="badssl.com",
			include_subdomains=True,
		)

		self.assertEqual(default_links, ["https://badssl.com/about"])
		self.assertEqual(
			wide_links,
			[
				"https://expired.badssl.com/",
				"https://badssl.com/about",
			],
		)

	def test_domain_crawl_follows_http_and_custom_ports_of_subdomains(self):
		html = (
			'<a href="http://http.badssl.com/">HTTP</a>'
			'<a href="https://tls-v1-0.badssl.com:1010/">TLS 1.0</a>'
			'<a href="http://example.org/">External</a>'
		).encode()
		response = SimpleNamespace(
			status_code=200,
			headers={"Content-Type": "text/html"},
			encoding="utf-8",
			iter_content=lambda chunk_size: [html],
		)

		links, _ = same_origin_links(
			"https://badssl.com/",
			response,
			scope_host="badssl.com",
			include_subdomains=True,
		)

		self.assertEqual(
			links,
			["http://http.badssl.com/", "https://tls-v1-0.badssl.com:1010/"],
		)

	def test_scan_website_checks_transport_once_per_host(self):
		host_levels = []

		def fake_scan(
			page_url,
			discover_links,
			site_level,
			scope_host,
			include_subdomains,
			host_level=None,
			deep=False,
		):
			host_levels.append((page_url, host_level))
			links = [
				"https://badssl.com/dashboard/",
				"https://expired.badssl.com/",
				"https://tls-v1-0.badssl.com:1010/",
			] if page_url == "https://badssl.com/" else []
			return {"http_status": 200, "findings": [], "checks": [], "discovered_links": links}

		with (
			patch("webaudit.scanner.crawler.validate_target", return_value="https://badssl.com/"),
			patch("webaudit.scanner.crawler.scan_security_headers", side_effect=fake_scan),
		):
			scan_website("https://badssl.com/", crawl=True)

		self.assertEqual(
			host_levels,
			[
				("https://badssl.com/", True),
				("https://badssl.com/dashboard/", False),
				("https://expired.badssl.com/", True),
				("https://tls-v1-0.badssl.com:1010/", True),
			],
		)

	def test_registrable_domain_handles_subdomains_public_suffixes_and_ips(self):
		self.assertEqual(registrable_domain("www.badssl.com"), "badssl.com")
		self.assertEqual(registrable_domain("expired.badssl.com"), "badssl.com")
		self.assertEqual(registrable_domain("shop.example.co.uk"), "example.co.uk")
		self.assertEqual(registrable_domain("notbadssl.com"), "notbadssl.com")
		self.assertEqual(registrable_domain("8.8.8.8"), "8.8.8.8")

	def test_fetch_retries_untrusted_https_certificate_without_verifying_it(self):
		response = object()
		with patch(
			"webaudit.scanner.network.requests.request",
			side_effect=[requests.exceptions.SSLError("certificate verify failed"), response],
		) as request_mock:
			result = fetch("https://expired.badssl.com/")

		self.assertIs(result, response)
		self.assertTrue(request_mock.call_args_list[0].kwargs["verify"])
		self.assertFalse(request_mock.call_args_list[1].kwargs["verify"])

	def test_fetch_falls_back_to_legacy_tls_for_weak_servers(self):
		response = object()
		with (
			patch(
				"webaudit.scanner.network.requests.request",
				side_effect=requests.exceptions.SSLError("dh key too small"),
			),
			patch(
				"webaudit.scanner.network.requests.Session.request",
				return_value=response,
			) as session_mock,
		):
			result = fetch("https://dh1024.badssl.com/")

		self.assertIs(result, response)
		self.assertFalse(session_mock.call_args.kwargs["verify"])

	def test_scan_website_stops_at_page_limit_and_aggregates_findings(self):
		pages = [f"https://example.com/page-{index}" for index in range(60)]
		calls = []

		def fake_scan(
			page_url,
			discover_links,
			site_level,
			scope_host,
			include_subdomains,
			host_level=None,
			deep=False,
		):
			calls.append((
				page_url,
				discover_links,
				site_level,
				scope_host,
				include_subdomains,
			))
			links = pages if page_url == "https://example.com/" else []
			return {
				"http_status": 200,
				"findings": [{
					"id": "WEB-TEST",
					"severity": "low",
					"deduction": 1,
				}],
				"checks": [],
				"discovered_links": links,
			}

		with (
			patch("webaudit.scanner.crawler.validate_target", return_value="https://example.com/"),
			patch("webaudit.scanner.crawler.scan_security_headers", side_effect=fake_scan),
			patch("webaudit.scanner.crawler.MAX_CRAWL_PAGES", 50),
		):
			result = scan_website("https://example.com/", crawl=True)

		self.assertEqual(result["pages_scanned"], 50)
		self.assertEqual(len(calls), 50)
		self.assertEqual(result["findings_count"], 50)
		self.assertFalse(result["crawl_complete"])
		self.assertEqual(result["crawl_stop_reason"], "page_limit")
		self.assertTrue(calls[0][2])
		self.assertTrue(all(not call[2] for call in calls[1:]))
		self.assertTrue(all(call[1] for call in calls))
		self.assertEqual(calls[0][3:], ("example.com", True))

	def test_scan_website_defaults_to_single_page_without_discovery(self):
		calls = []

		def fake_scan(
			page_url,
			discover_links,
			site_level,
			scope_host,
			include_subdomains,
			host_level=None,
			deep=False,
		):
			calls.append((
				page_url,
				discover_links,
				site_level,
				scope_host,
				include_subdomains,
			))
			return {
				"http_status": 200,
				"findings": [],
				"checks": [],
			}

		with (
			patch("webaudit.scanner.crawler.validate_target", return_value="https://example.com/"),
			patch("webaudit.scanner.crawler.scan_security_headers", side_effect=fake_scan),
		):
			result = scan_website("https://example.com/")

		self.assertEqual(result["pages_scanned"], 1)
		self.assertEqual(result["page_limit"], 1)
		self.assertTrue(result["crawl_complete"])
		self.assertEqual(
			calls,
			[("https://example.com/", False, True, "example.com", False)],
		)

	def test_scan_website_uses_registrable_domain_as_subdomain_scope(self):
		calls = []

		def fake_scan(
			page_url,
			discover_links,
			site_level,
			scope_host,
			include_subdomains,
			host_level=None,
			deep=False,
		):
			calls.append((scope_host, include_subdomains))
			return {"http_status": 200, "findings": [], "checks": []}

		with (
			patch(
				"webaudit.scanner.crawler.validate_target",
				return_value="https://www.badssl.com/",
			),
			patch("webaudit.scanner.crawler.scan_security_headers", side_effect=fake_scan),
		):
			scan_website("https://www.badssl.com/", crawl=True)

		self.assertEqual(calls, [("badssl.com", True)])

	def test_scan_website_endpoint_returns_crawl_result(self):
		with patch(
			"web.server.scan_website",
			return_value={"pages_scanned": 2, "findings": []},
		) as scan_mock:
			response = client.post(
				"/scan/website",
				json={"target": "https://example.com"},
			)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()["pages_scanned"], 2)
		scan_mock.assert_called_once_with("https://example.com/", crawl=False, deep=False, max_pages=None, max_seconds=None)

		with patch(
			"web.server.scan_website",
			return_value={"pages_scanned": 3, "findings": []},
		) as scan_mock:
			response = client.post(
				"/scan/website",
				json={"target": "https://example.com", "crawl": True},
			)

		self.assertEqual(response.status_code, 200)
		scan_mock.assert_called_once_with("https://example.com/", crawl=True, deep=False, max_pages=None, max_seconds=None)

	def test_scan_website_reports_progress_and_stops_when_cancelled(self):
		progress = []
		scanned = []

		def fake_scan(page_url, discover_links, site_level, scope_host, include_subdomains, host_level=None, deep=False):
			scanned.append(page_url)
			links = [f"https://example.com/p{index}" for index in range(5)] if page_url == "https://example.com/" else []
			return {"http_status": 200, "findings": [{"id": "WEB-TEST", "severity": "low"}], "checks": [], "discovered_links": links}

		with (
			patch("webaudit.scanner.crawler.validate_target", return_value="https://example.com/"),
			patch("webaudit.scanner.crawler.scan_security_headers", side_effect=fake_scan),
		):
			result = scan_website(
				"https://example.com/",
				crawl=True,
				on_progress=progress.append,
				should_cancel=lambda: len(scanned) >= 2,
			)

		self.assertEqual(len(scanned), 2)
		self.assertEqual(result["pages_scanned"], 2)
		self.assertEqual(result["findings_count"], 2)
		self.assertEqual(result["crawl_stop_reasons"][0], "cancelled")
		self.assertFalse(result["crawl_complete"])
		self.assertEqual(progress[0]["current_page"], "https://example.com/")
		self.assertEqual(progress[1]["queued"], 4)
		self.assertIsNone(progress[-1]["current_page"])
		self.assertEqual(progress[-1]["findings"], 2)

	def test_scan_job_endpoints_report_progress_result_and_cancel(self):
		release = threading.Event()

		def fake_scan(target, crawl, on_progress, should_cancel, **options):
			on_progress({"pages_scanned": 0, "page_limit": 150, "queued": 0, "current_page": target, "findings": 0})
			release.wait(5)
			cancelled = should_cancel()
			return {"findings": [], "pages_scanned": 1, "crawl_stop_reasons": ["cancelled"] if cancelled else []}

		with patch("webaudit.jobs.scan_website", side_effect=fake_scan):
			job_id = client.post("/scan/jobs", json={"target": "https://example.com", "crawl": True}).json()["id"]
			running = client.get(f"/scan/jobs/{job_id}").json()
			cancelling = client.delete(f"/scan/jobs/{job_id}").json()
			release.set()
			for _ in range(50):
				final = client.get(f"/scan/jobs/{job_id}").json()
				if final["state"] != "running":
					break
				time.sleep(0.05)

		self.assertEqual(running["state"], "running")
		self.assertEqual(running["progress"]["current_page"], "https://example.com/")
		self.assertTrue(cancelling["cancel_requested"])
		self.assertEqual(final["state"], "cancelled")
		self.assertEqual(final["result"]["crawl_stop_reasons"], ["cancelled"])
		self.assertEqual(client.get("/scan/jobs/missing").status_code, 404)

	def test_scan_job_reports_connection_errors(self):
		with patch("webaudit.jobs.scan_website", side_effect=requests.ConnectionError()):
			job_id = client.post("/scan/jobs", json={"target": "https://example.com"}).json()["id"]
			for _ in range(50):
				job = client.get(f"/scan/jobs/{job_id}").json()
				if job["state"] != "running":
					break
				time.sleep(0.05)

		self.assertEqual(job["state"], "error")
		self.assertEqual(job["error"], "No se pudo conectar con el sitio web.")

	def test_every_scanner_text_has_an_english_translation(self):
		"""Cada texto que el escáner muestra al usuario debe estar en i18n-scanner.js."""
		import ast
		import re
		from pathlib import Path

		project = Path(__file__).resolve().parent.parent
		root = project / "webaudit"
		catalog = (project / "web" / "static" / "js" / "i18n-scanner.js").read_text(encoding="utf-8")
		translated = set(re.findall(r'^\s*"(.+?)":', catalog, re.MULTILINE))

		# Textos sin idioma (nombres de cabeceras, categorías OWASP en inglés...)
		neutral = {
			"Auditor de seguridad web",  # Descripción de la API, no se muestra
			"HTTP Strict Transport Security",
			"Access-Control-Allow-Origin: *",
			"Referrer-Policy: unsafe-url",
		}
		missing = []
		for path in [root / "jobs.py", *sorted((root / "scanner").glob("*.py"))]:
			tree = ast.parse(path.read_text(encoding="utf-8"))
			docstrings = {
				id(node.body[0].value)
				for node in ast.walk(tree)
				if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef))
				and node.body and isinstance(node.body[0], ast.Expr)
				and isinstance(node.body[0].value, ast.Constant)
			}
			for node in ast.walk(tree):
				if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
					continue
				text = node.value
				if id(node) in docstrings or text in neutral or text.endswith(": "):
					continue
				if " " in text and re.search(r"[a-záéíóúñ]{3}", text) and not text.startswith(("A0", "http")):
					if text not in translated:
						missing.append(f"{path.name}: {text}")

		self.assertEqual(missing, [])

	# --- Contenido mixto y SRI ---------------------------------------------------

	def _parsed_page(self, html):
		from webaudit.scanner.html_page import read_page

		response = SimpleNamespace(
			status_code=200,
			headers={"Content-Type": "text/html"},
			encoding="utf-8",
			iter_content=lambda chunk_size: [html.encode()],
		)
		return read_page(response)

	def test_mixed_content_separates_active_passive_and_forms(self):
		from webaudit.scanner.page_checks import check_mixed_content
		from webaudit.scanner.results import Report

		page = self._parsed_page(
			'<script src="http://cdn.example/app.js"></script>'
			'<link rel="stylesheet" href="http://cdn.example/site.css">'
			'<img src="http://img.example/a.png"><img src="/local.png">'
			'<form action="http://example.com/login"></form>'
			'<script src="https://cdn.example/ok.js"></script>'
		)
		report = Report()
		check_mixed_content(report, page, "https://example.com/")

		ids = {finding["id"]: finding for finding in report.findings}
		self.assertEqual(set(ids), {"WEB-MIXED-ACTIVE", "WEB-MIXED-PASSIVE", "WEB-MIXED-FORM"})
		self.assertIn("http://cdn.example/app.js", ids["WEB-MIXED-ACTIVE"]["evidence"])
		self.assertIn("http://cdn.example/site.css", ids["WEB-MIXED-ACTIVE"]["evidence"])
		self.assertEqual(ids["WEB-MIXED-ACTIVE"]["severity"], "medium")
		self.assertEqual(ids["WEB-MIXED-PASSIVE"]["severity"], "low")
		self.assertEqual(report.checks[0]["status"], "fail")

	def test_subresource_integrity_only_flags_external_scripts_and_styles(self):
		from webaudit.scanner.page_checks import check_subresource_integrity
		from webaudit.scanner.results import Report

		page = self._parsed_page(
			'<script src="/own.js"></script>'
			'<script src="https://cdn.example/lib.js" integrity="sha384-abc"></script>'
			'<script src="https://cdn.example/tracker.js"></script>'
			'<link rel="stylesheet" href="https://fonts.example/f.css">'
			'<img src="https://img.example/a.png">'
		)
		report = Report()
		check_subresource_integrity(report, page, "https://example.com/")

		self.assertEqual(len(report.findings), 1)
		finding = report.findings[0]
		self.assertEqual(finding["id"], "WEB-SRI-MISSING")
		self.assertIn("tracker.js", finding["evidence"])
		self.assertIn("f.css", finding["evidence"])
		self.assertNotIn("lib.js", finding["evidence"])
		self.assertIn("A08:2025", finding["owasp_category"])
		self.assertEqual(finding["i18n"]["title"]["params"], {"count": "2"})

	# --- TLS -----------------------------------------------------------------------

	def _certificate(self, issuer_name="Intermediate CA", days_valid=90, key_bits=2048):
		import datetime as dt

		from cryptography import x509
		from cryptography.hazmat.primitives import hashes
		from cryptography.hazmat.primitives.asymmetric import rsa
		from cryptography.x509.oid import NameOID

		key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
		now = dt.datetime.now(dt.timezone.utc)
		return (
			x509.CertificateBuilder()
			.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")]))
			.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
			.public_key(key.public_key())
			.serial_number(1234)
			.not_valid_before(now - dt.timedelta(days=1))
			.not_valid_after(now + dt.timedelta(days=days_valid))
			.sign(key, hashes.SHA256())
		)

	def _run_tls_checks(self, handshakes, versions, revocation):
		from webaudit.scanner import tls
		from webaudit.scanner.results import Report
		from webaudit.scanner.tls_checks import check_tls

		report = Report()
		with (
			patch("webaudit.scanner.tls_checks.tls.handshake", side_effect=handshakes),
			patch("webaudit.scanner.tls_checks.tls.supported_tls_versions", return_value=versions),
			patch("webaudit.scanner.tls_checks.tls.check_revocation", return_value=tls.Revocation(*revocation)),
		):
			check_tls(report, "example.com", 443)
		return report

	def test_tls_incomplete_chain_is_told_apart_from_untrusted_issuer(self):
		import ssl

		from webaudit.scanner.tls import Handshake

		error = ssl.SSLCertVerificationError("unable to get local issuer certificate")
		error.verify_code = 20
		error.verify_message = "unable to get local issuer certificate"
		leaf_only = Handshake("TLSv1.3", "TLS_AES_256_GCM_SHA384", [self._certificate()])

		report = self._run_tls_checks(
			[error, leaf_only], ["TLSv1.2", "TLSv1.3"], ("good", "CRL", "http://crl.example/1.crl"),
		)

		ids = [finding["id"] for finding in report.findings]
		self.assertEqual(ids, ["WEB-TLS-INCOMPLETE-CHAIN"])
		statuses = {check["id"]: check["status"] for check in report.checks}
		self.assertEqual(statuses["TLS-VERSIONS"], "pass")
		self.assertEqual(statuses["TLS-REVOCATION"], "pass")

	def test_tls_reports_obsolete_versions_revocation_and_short_keys(self):
		from webaudit.scanner.tls import Handshake

		valid = Handshake("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", [self._certificate(key_bits=1024)])

		report = self._run_tls_checks(
			[valid], ["TLSv1", "TLSv1.1", "TLSv1.2"], ("revoked", "OCSP", "2026-09-15"),
		)

		findings = {finding["id"]: finding for finding in report.findings}
		self.assertEqual(
			set(findings), {"WEB-TLS-WEAK-KEY", "WEB-TLS-PROTOCOL", "WEB-TLS-REVOKED"},
		)
		self.assertIn("TLSv1, TLSv1.1", findings["WEB-TLS-PROTOCOL"]["title"])
		# Con TLS 1.2 disponible, el riesgo se limita a clientes antiguos
		self.assertEqual(findings["WEB-TLS-PROTOCOL"]["severity"], "medium")
		self.assertIn("2026-09-15", findings["WEB-TLS-REVOKED"]["evidence"])
		self.assertIn("1024", findings["WEB-TLS-WEAK-KEY"]["title"])

	def test_tls_only_obsolete_versions_is_high_severity(self):
		from webaudit.scanner.tls import Handshake

		old_only = Handshake("TLSv1", "ECDHE-RSA-AES256-SHA", [self._certificate()])
		report = self._run_tls_checks([old_only], ["TLSv1"], ("good", "CRL", "http://crl.example/1.crl"))

		protocol = next(f for f in report.findings if f["id"] == "WEB-TLS-PROTOCOL")
		self.assertEqual(protocol["severity"], "high")

	def test_tls_version_counts_only_if_actually_negotiated(self):
		from webaudit.scanner import tls

		# El servidor ignora la versión pedida y negocia TLS 1.2 en todas las pruebas
		with patch("webaudit.scanner.tls.handshake", return_value=tls.Handshake("TLSv1.2", "x", [])):
			versions = tls.supported_tls_versions("example.com", 443, "TLSv1.3")
		self.assertEqual(versions, ["TLSv1.2", "TLSv1.3"])

	def test_crl_check_requires_issuer_signature_and_finds_revoked_serial(self):
		import datetime as dt

		from cryptography import x509
		from cryptography.hazmat.primitives import hashes, serialization
		from cryptography.hazmat.primitives.asymmetric import rsa
		from cryptography.x509.oid import NameOID

		from webaudit.scanner import tls

		issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
		issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
		now = dt.datetime.now(dt.timezone.utc)
		issuer = (
			x509.CertificateBuilder().subject_name(issuer_name).issuer_name(issuer_name)
			.public_key(issuer_key.public_key()).serial_number(1)
			.not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
			.sign(issuer_key, hashes.SHA256())
		)
		leaf = self._certificate()
		revoked_entry = (
			x509.RevokedCertificateBuilder().serial_number(leaf.serial_number)
			.revocation_date(now - dt.timedelta(days=2)).build()
		)

		def crl(signing_key):
			return (
				x509.CertificateRevocationListBuilder().issuer_name(issuer_name)
				.last_update(now).next_update(now + dt.timedelta(days=1))
				.add_revoked_certificate(revoked_entry).sign(signing_key, hashes.SHA256())
				.public_bytes(serialization.Encoding.DER)
			)

		tls._download_crl.cache_clear()
		with patch("webaudit.scanner.tls._download", return_value=crl(issuer_key)):
			result = tls._check_crl(leaf, issuer, "http://crl.example/1.crl")
		self.assertEqual(result.status, "revoked")

		tls._download_crl.cache_clear()
		with patch("webaudit.scanner.tls._download", return_value=crl(other_key)):
			forged = tls._check_crl(leaf, issuer, "http://crl.example/1.crl")
		self.assertEqual(forged.status, "unknown")

	def test_revocation_downloads_reject_private_addresses(self):
		from webaudit.scanner import tls

		with patch("webaudit.scanner.tls.requests.request") as request_mock:
			self.assertIsNone(tls._download("http://127.0.0.1/evil.crl"))
		request_mock.assert_not_called()

	# --- Historial -------------------------------------------------------------------

	def test_history_saves_lists_loads_and_deletes_scans(self):
		from webaudit import history

		result = {"target": "https://example.com/", "findings_count": 3, "summary": {"high": 1}, "findings": []}
		saved = history.save("https://example.com/", False, "done", result)

		listed = client.get("/history").json()
		self.assertEqual(listed[0]["id"], saved["id"])
		self.assertEqual(listed[0]["summary"], {"high": 1})
		self.assertNotIn("result", listed[0])  # La lista solo trae el resumen

		entry = client.get(f"/history/{saved['id']}").json()
		self.assertEqual(entry["result"]["findings_count"], 3)

		self.assertEqual(client.delete(f"/history/{saved['id']}").status_code, 200)
		self.assertEqual(client.get(f"/history/{saved['id']}").status_code, 404)

	def test_history_rejects_ids_outside_its_folder(self):
		from webaudit import history

		self.assertIsNone(history.load("../../secret"))
		self.assertFalse(history.delete("..\..\secret"))
		self.assertEqual(client.get("/history/..%2F..%2Fsecret").status_code, 404)

	def test_history_keeps_only_the_most_recent_entries(self):
		from webaudit import history

		with patch("webaudit.history.MAX_ENTRIES", 3):
			for index in range(5):
				history.save(f"https://example.com/{index}", False, "done", {})
				time.sleep(0.01)
			targets = [entry["target"] for entry in history.list_entries()]

		self.assertEqual(len(targets), 3)

	def test_finished_job_is_saved_to_history(self):
		def fake_scan(target, crawl, on_progress, should_cancel, **options):
			return {"target": target, "findings_count": 0, "summary": {}, "findings": [], "checks": []}

		with patch("webaudit.jobs.scan_website", side_effect=fake_scan):
			job_id = client.post("/scan/jobs", json={"target": "https://history.example"}).json()["id"]
			for _ in range(50):
				job = client.get(f"/scan/jobs/{job_id}").json()
				if job["state"] != "running":
					break
				time.sleep(0.05)

		self.assertEqual(job["state"], "done")
		saved = job["history_entry"]
		self.assertEqual(saved["target"], "https://history.example/")
		self.assertIn(saved["id"], [entry["id"] for entry in client.get("/history").json()])

	# --- Cookies, CSP y versiones ----------------------------------------------------

	def test_cookie_prefixes_and_long_session_cookies(self):
		from webaudit.scanner.page_checks import check_cookies
		from webaudit.scanner.results import Report

		report = Report()
		check_cookies(report, [
			"__Host-sid=1; Secure; Path=/; HttpOnly; SameSite=Lax",
			"__Host-bad=1; Secure; Path=/app; Domain=example.com; HttpOnly; SameSite=Lax",
			"__Secure-x=1; HttpOnly; SameSite=Lax",
			"session=1; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000",
		], is_https=True)

		prefix_titles = [f["title"] for f in report.findings if f["id"] == "WEB-COOKIE-PREFIX"]
		self.assertEqual(len(prefix_titles), 2)
		self.assertTrue(any("__Host-bad" in title for title in prefix_titles))
		self.assertTrue(any("__Secure-x" in title for title in prefix_titles))
		long_session = [f for f in report.findings if f["id"] == "WEB-COOKIE-LONG-SESSION"]
		self.assertEqual(len(long_session), 1)
		self.assertIn("365", long_session[0]["title"])

	def test_csp_nonce_makes_unsafe_inline_safe_and_style_inline_is_low(self):
		issues = analyze_csp(
			"script-src 'self' 'nonce-abc123' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
			"object-src 'none'; base-uri 'self'"
		)
		titles = {issue.title: issue.severity for issue in issues}
		self.assertNotIn("La CSP permite 'unsafe-inline'", titles)
		self.assertEqual(titles["La CSP permite estilos inline ('unsafe-inline')"], "low")

	def test_report_only_csp_is_reported(self):
		from webaudit.scanner.page_checks import check_csp
		from webaudit.scanner.results import Report

		report = Report()
		check_csp(report, {"content-security-policy-report-only": "default-src 'self'"})
		self.assertEqual([f["id"] for f in report.findings], ["WEB-CSP-REPORT-ONLY"])

	def test_outdated_server_software_is_reported(self):
		from webaudit.scanner.page_checks import check_information_disclosure
		from webaudit.scanner.results import Report

		report = Report()
		check_information_disclosure(report, {
			"server": "Apache/2.2.15 (CentOS)",
			"x-powered-by": "PHP/8.3.1",
		})
		outdated = [f for f in report.findings if f["id"] == "WEB-INFO-OUTDATED"]
		self.assertEqual(len(outdated), 1)
		self.assertIn("Apache/2.2.15", outdated[0]["title"])
		self.assertNotIn("PHP", outdated[0]["title"])

	# --- DNS, archivos expuestos, favicon y sitemap ------------------------------------

	def test_dns_checks_spf_dmarc_and_caa(self):
		from webaudit.scanner import dns_checks
		from webaudit.scanner.results import Report

		records = {
			("example.com", "TXT"): ["v=spf1 include:_spf.example.net +all", "google-site-verification=x"],
			("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:d@example.com"],
			("example.com", "CAA"): [],
		}

		def fake_txt(name):
			return records[(name, "TXT")]

		def fake_query(name, record_type):
			return records[(name, record_type)]

		report = Report()
		with (
			patch("webaudit.scanner.dns_checks._txt_records", side_effect=fake_txt),
			patch("webaudit.scanner.dns_checks._query", side_effect=fake_query),
		):
			dns_checks.check_dns(report, "www.example.com")

		ids = [finding["id"] for finding in report.findings]
		self.assertEqual(ids, ["WEB-DNS-SPF-PERMISSIVE", "WEB-DNS-DMARC-NONE", "WEB-DNS-CAA-MISSING"])

	def test_dns_timeouts_are_reported_as_unknown(self):
		from webaudit.scanner import dns_checks
		from webaudit.scanner.results import Report

		report = Report()
		with patch("webaudit.scanner.dns_checks._query", side_effect=dns_checks.DnsUnavailable()):
			dns_checks.check_dns(report, "example.com")
		self.assertEqual({check["status"] for check in report.checks}, {"unknown"})
		self.assertEqual(report.findings, [])

	def test_exposed_files_require_matching_content(self):
		from urllib.parse import urlparse

		from webaudit.scanner import site_checks
		from webaudit.scanner.results import Report

		responses = {
			"https://example.com/.git/HEAD": (200, b"ref: refs/heads/main\n"),
			# Una página de error que responde 200 a todo no cuenta como .env
			"https://example.com/.env": (200, b"<!doctype html><title>Not found</title>"),
		}
		report = Report()
		with patch(
			"webaudit.scanner.site_checks._read_start",
			side_effect=lambda url: responses.get(url, (404, b"")),
		):
			site_checks.check_exposed_files(report, urlparse("https://example.com/"))

		self.assertEqual([f["title"] for f in report.findings], ["Repositorio Git expuesto (/.git/)"])
		self.assertEqual(report.findings[0]["severity"], "high")

	def test_favicon_redirect_to_http_is_mixed_content(self):
		from urllib.parse import urlparse

		from webaudit.scanner import site_checks
		from webaudit.scanner.results import Report

		report = Report()

		class FakeResponse:
			status_code = 301
			headers = {"Location": "http://example.com/favicon.ico"}
			def __enter__(self): return self
			def __exit__(self, *args): return False

		with patch("webaudit.scanner.site_checks.fetch", return_value=FakeResponse()):
			site_checks.check_favicon_redirect(report, urlparse("https://example.com/"))
		self.assertEqual([f["id"] for f in report.findings], ["WEB-MIXED-FAVICON"])

	def test_sitemap_links_follow_index_and_stay_in_scope(self):
		from webaudit.scanner import links

		files = {
			"https://example.com/robots.txt": b"User-agent: *\nSitemap: https://example.com/index.xml\n",
			"https://example.com/index.xml": (
				b"<sitemapindex><sitemap><loc>https://example.com/pages.xml</loc></sitemap></sitemapindex>"
			),
			"https://example.com/pages.xml": (
				b"<urlset><url><loc>https://example.com/a?x=1&amp;y=2</loc></url>"
				b"<url><loc>https://blog.example.com/post</loc></url>"
				b"<url><loc>https://other.org/out</loc></url></urlset>"
			),
		}
		with patch("webaudit.scanner.links._read_text", side_effect=files.get):
			found = links.sitemap_links("https://example.com/", "example.com", include_subdomains=True)

		self.assertEqual(found, ["https://example.com/a?x=1&y=2", "https://blog.example.com/post"])

	def test_crawl_adds_sitemap_pages_and_respects_custom_limits(self):
		scanned = []

		def fake_scan(page_url, discover_links, site_level, scope_host, include_subdomains, host_level=None, deep=False):
			scanned.append((page_url, deep))
			return {"http_status": 200, "findings": [], "checks": [], "discovered_links": []}

		sitemap = [f"https://example.com/s{index}" for index in range(10)]
		with (
			patch("webaudit.scanner.crawler.validate_target", return_value="https://example.com/"),
			patch("webaudit.scanner.crawler.scan_security_headers", side_effect=fake_scan),
			patch("webaudit.scanner.crawler.sitemap_links", return_value=sitemap),
		):
			result = scan_website("https://example.com/", crawl=True, deep=True, max_pages=4)

		self.assertEqual([url for url, _ in scanned], ["https://example.com/", *sitemap[:3]])
		self.assertTrue(all(deep for _, deep in scanned))
		self.assertEqual(result["page_limit"], 4)
		self.assertTrue(result["deep"])

	def test_scan_options_are_validated_and_passed_to_the_scan(self):
		with patch("web.server.scan_website", return_value={"findings": []}) as scan_mock:
			ok = client.post("/scan/website", json={
				"target": "https://example.com", "crawl": True, "deep": True, "max_pages": 20, "max_minutes": 2,
			})
			too_many = client.post("/scan/website", json={"target": "https://example.com", "max_pages": 9999})

		self.assertEqual(ok.status_code, 200)
		scan_mock.assert_called_once_with(
			"https://example.com/", crawl=True, deep=True, max_pages=20, max_seconds=120,
		)
		self.assertEqual(too_many.status_code, 422)

	def test_history_finds_previous_scan_of_the_same_site_and_mode(self):
		from webaudit import history

		older = history.save("https://compare.example/", False, "done", {"findings": [{"id": "A"}]})
		time.sleep(0.01)
		history.save("https://compare.example/", True, "done", {"findings": []})  # Otro alcance
		time.sleep(0.01)
		history.save("https://other.example/", False, "done", {"findings": []})  # Otro sitio
		time.sleep(0.01)
		newer = history.save("https://compare.example/", False, "done", {"findings": []})

		previous = client.get(f"/history/{newer['id']}/previous")
		self.assertEqual(previous.json()["id"], older["id"])
		self.assertEqual(client.get(f"/history/{older['id']}/previous").status_code, 404)
