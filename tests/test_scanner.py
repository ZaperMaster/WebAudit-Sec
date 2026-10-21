import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
import requests

from app.scanner import (
	add_finding,
	analyze_csp,
	analyze_security_header_values,
	build_scan_result,
	cookie_attribute_names,
	fetch,
	same_origin_links,
	set_cookie_headers,
	scan_website,
)
from app.main import app


client = TestClient(app)

class ScannerGuidanceTests(unittest.TestCase):
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
			15,
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

		with patch("app.scanner.MAX_LINKS_PER_PAGE", 1):
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

	def test_fetch_retries_untrusted_https_certificate_without_verifying_it(self):
		response = object()
		with patch(
			"app.scanner.requests.request",
			side_effect=[requests.exceptions.SSLError("certificate verify failed"), response],
		) as request_mock:
			result = fetch("https://expired.badssl.com/")

		self.assertIs(result, response)
		self.assertTrue(request_mock.call_args_list[0].kwargs["verify"])
		self.assertFalse(request_mock.call_args_list[1].kwargs["verify"])

	def test_scan_website_stops_at_page_limit_and_aggregates_findings(self):
		pages = [f"https://example.com/page-{index}" for index in range(60)]
		calls = []

		def fake_scan(
			page_url,
			discover_links,
			site_level,
			scope_host,
			include_subdomains,
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
			patch("app.scanner.validate_target", return_value="https://example.com/"),
			patch("app.scanner.scan_security_headers", side_effect=fake_scan),
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
			patch("app.scanner.validate_target", return_value="https://example.com/"),
			patch("app.scanner.scan_security_headers", side_effect=fake_scan),
		):
			result = scan_website("https://example.com/")

		self.assertEqual(result["pages_scanned"], 1)
		self.assertEqual(result["page_limit"], 1)
		self.assertTrue(result["crawl_complete"])
		self.assertEqual(
			calls,
			[("https://example.com/", False, True, "example.com", False)],
		)

	def test_scan_website_endpoint_returns_crawl_result(self):
		with patch(
			"app.main.scan_website",
			return_value={"pages_scanned": 2, "findings": []},
		) as scan_mock:
			response = client.post(
				"/scan/website",
				json={"target": "https://example.com"},
			)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.json()["pages_scanned"], 2)
		scan_mock.assert_called_once_with("https://example.com/", crawl=False)

		with patch(
			"app.main.scan_website",
			return_value={"pages_scanned": 3, "findings": []},
		) as scan_mock:
			response = client.post(
				"/scan/website",
				json={"target": "https://example.com", "crawl": True},
			)

		self.assertEqual(response.status_code, 200)
		scan_mock.assert_called_once_with("https://example.com/", crawl=True)

