.PHONY: help debug release sanitized test-debug test-release test-sanitized \
	lint tidy format clean lint-tidy-note clang-format-config

CORE_SOURCES := \
	main.cpp \
	$(wildcard platform/*.cppm network/*.cppm processors/*.cppm sniffer/*.cppm) \
	$(wildcard tests/*.cpp tests/manual/*.cpp)

TOOLS_FILE := tools.json
PROJECT_ROOT := $(patsubst %/,%,$(abspath $(dir $(lastword $(MAKEFILE_LIST)))))
LINT_TOOL := $(or $(strip $(shell sed -n 's/.*"lint_tool": *"\([^"]*\)".*/\1/p' $(TOOLS_FILE) | head -n 1)),clang-tidy)
TIDY_TOOL := $(or $(strip $(shell sed -n 's/.*"tidy_tool": *"\([^"]*\)".*/\1/p' $(TOOLS_FILE) | head -n 1)),clang-tidy)
FORMAT_TOOL := $(or $(strip $(shell sed -n 's/.*"format_tool": *"\([^"]*\)".*/\1/p' $(TOOLS_FILE) | head -n 1)),clang-format)

FORMAT_SOURCES := \
	$(CORE_SOURCES) \
	$(wildcard platform/*.hpp platform/*.h network/*.hpp network/*.h) \
	$(wildcard processors/*.hpp processors/*.h sniffer/*.hpp sniffer/*.h) \
	$(wildcard tests/*.hpp tests/*.h)

CLANG_TIDY_CHECKS := -checks='-*,modernize-*,bugprone-use-after-move,clang-analyzer-*,clang-diagnostic-*,\
-clang-analyzer-optin.core.EnumCastOutOfRange,-modernize-use-trailing-return-type,-modernize-avoid-c-arrays,\
-modernize-use-scoped-lock'

CLANG_TIDY_HEADER_FILTER := \
	-header-filter='^$(PROJECT_ROOT)/(platform|network|processors|sniffer|tests)/' \
	--exclude-header-filter='^$(PROJECT_ROOT)/build/'

LINT_TIDY_BASE = $(LINT_TOOL) --quiet -p build/debug $(CLANG_TIDY_CHECKS) $(CLANG_TIDY_HEADER_FILTER)

FIX_TIDY_BASE = $(TIDY_TOOL) --quiet -p build/debug $(CLANG_TIDY_CHECKS) $(CLANG_TIDY_HEADER_FILTER)
LINT_PARALLEL = xargs -r -n 1 -P $(PARALLEL_THREADS)

# CLANG_FORMAT_STYLE := "{BasedOnStyle: llvm, IndentWidth: 4, ColumnLimit: 85}"
CLANG_FORMAT_STYLE := file
PARALLEL_THREADS ?= 8
BUILD_PARALLEL := --parallel $(PARALLEL_THREADS)
CTEST_PARALLEL := --parallel $(PARALLEL_THREADS)

help: ## Show available make targets
	@awk 'BEGIN {FS=":.*## "}; /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-16s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

lint: lint-tidy-note debug ## Run clang-tidy checks on all C++ source/module files (requires debug build)
	@printf '%s\n' $(CORE_SOURCES) | $(LINT_PARALLEL) $(LINT_TIDY_BASE)

tidy: lint-tidy-note debug ## Run clang-tidy with in-place auto-fixes (requires debug build)
	@for file in $(CORE_SOURCES); do \
		$(FIX_TIDY_BASE) -fix "$$file" || exit $$?; \
	done

format: ## Run clang-format with LLVM-based style
	@for file in $(FORMAT_SOURCES); do \
		$(FORMAT_TOOL) -i -style=$(CLANG_FORMAT_STYLE) "$$file" || exit $$?; \
	done

lint-tidy-note:
	@echo "Info: lint/tidy use build/debug compile_commands and trigger debug build when needed."

debug: ## Configure and build debug preset
	cmake --preset debug
	cmake --build --preset debug $(BUILD_PARALLEL)

release: ## Configure and build release preset
	cmake --preset release
	cmake --build --preset release $(BUILD_PARALLEL)

sanitized: ## Configure and build sanitized preset
	cmake --preset sanitized
	cmake --build --preset sanitized $(BUILD_PARALLEL)

test-debug: ## Run tests in debug preset
	ctest --preset debug $(CTEST_PARALLEL)

test-release: ## Run tests in release preset
	ctest --preset release $(CTEST_PARALLEL)

test-sanitized: ## Run tests in sanitized preset
	ctest --preset sanitized $(CTEST_PARALLEL)

clean: ## Remove all build artifacts
	rm -rf build
