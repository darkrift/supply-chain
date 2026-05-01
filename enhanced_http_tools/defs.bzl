"""Public API for HTTP repository rules that emit package metadata."""

load("//private:http.bzl", _enhanced_http_archive = "enhanced_http_archive", _enhanced_http_file = "enhanced_http_file")

enhanced_http_archive = _enhanced_http_archive
enhanced_http_file = _enhanced_http_file
