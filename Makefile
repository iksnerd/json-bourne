# UI build. The built CSS (internal/adapters/web/static/tailwind.css) and the generated
# *_templ.go files are committed, so `go build` and CI need none of these tools.
# Run `make ui` after changing a .templ file, a class name or assets/input.css.

TEMPL_VERSION    := v0.3.1020
TAILWIND_VERSION := v4.3.3
WEB              := internal/adapters/web

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
  TW_ASSET  := tailwindcss-macos-arm64
  TW_SHA256 := cdf646702987a743464dff4d9c60fd4480d1c1e73dd819a9a67f1078815dce9d
else
  TW_ASSET  := tailwindcss-linux-x64
  TW_SHA256 := dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a
endif

.PHONY: ui tools ui-check

ui: tools
	templ generate -path $(WEB)
	./bin/tailwindcss -i $(WEB)/assets/input.css -o $(WEB)/static/tailwind.css --minify

# tools installs the pinned templ CLI and downloads the pinned Tailwind standalone CLI,
# refusing it unless its SHA-256 is the one recorded above. On macOS the verified binary is
# then ad-hoc signed locally, because the kernel kills an unsigned arm64 binary; the
# stamp file records that this version was verified, so the signed copy is not re-checked.
TW_STAMP := bin/.tailwindcss-$(TAILWIND_VERSION)

tools:
	@command -v templ >/dev/null && templ version | grep -q '$(TEMPL_VERSION)' || go install github.com/a-h/templ/cmd/templ@$(TEMPL_VERSION)
	@mkdir -p bin
	@if [ ! -f $(TW_STAMP) ]; then \
	  curl -sSL -o bin/tailwindcss.download https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/$(TW_ASSET); \
	  echo "$(TW_SHA256)  bin/tailwindcss.download" | shasum -a 256 -c - || { rm -f bin/tailwindcss.download; exit 1; }; \
	  mv bin/tailwindcss.download bin/tailwindcss; chmod +x bin/tailwindcss; \
	  if [ "$(UNAME_S)" = Darwin ]; then codesign --force --sign - bin/tailwindcss; fi; \
	  touch $(TW_STAMP); \
	fi

# ui-check fails when the committed generated files are stale.
ui-check: ui
	git diff --exit-code -- $(WEB)
