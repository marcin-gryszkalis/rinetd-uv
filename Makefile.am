
AUTOMAKE_OPTIONS = foreign dist-zstd

SUBDIRS = src

EXTRA_DIST = bootstrap LICENSE CHANGES.md README.md DOCUMENTATION.md BUILD.md \
	TCP-UDP_MIXED_MODE.md \
	index.html rinetd.vcxproj generate-manpage.sh generate-html.sh generate-conf.sh \
	$(man_MANS) $(sysconf_DATA)

man_MANS = rinetd-uv.8
sysconf_DATA = rinetd-uv.conf
noinst_DATA = index.html

# Generate man page from DOCUMENTATION.md using pandoc (if available)
rinetd-uv.8: DOCUMENTATION.md
	@if which pandoc >/dev/null 2>&1; then \
		./generate-manpage.sh; \
	else \
		echo "Warning: pandoc not found, keeping existing rinetd-uv.8"; \
		touch $@; \
	fi

# Generate HTML from DOCUMENTATION.md using pandoc (if available)
# Falls back to roffit if pandoc is not available (for backward compatibility)
index.html: DOCUMENTATION.md
	@if which pandoc >/dev/null 2>&1; then \
		./generate-html.sh; \
	elif [ -f rinetd-uv.8 ] && which roffit >/dev/null 2>&1; then \
		echo "Using roffit to generate HTML from rinetd-uv.8..."; \
		roffit < rinetd-uv.8 > $@; \
	else \
		echo "Warning: neither pandoc nor roffit found, keeping existing index.html"; \
		touch $@; \
	fi

# Extract example configuration from DOCUMENTATION.md
rinetd-uv.conf: DOCUMENTATION.md
	@./generate-conf.sh

# Convenience targets for documentation generation
.PHONY: docs docs-man docs-html docs-conf

docs: docs-man docs-html docs-conf

docs-man: rinetd-uv.8

docs-html: index.html

docs-conf: rinetd-uv.conf

# This is for Travis CI; we don't have a testsuite yet.
test:
