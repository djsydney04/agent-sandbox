#!/bin/sh
# Bundle the tracked project with a native CLI; never include local credentials.
set -eu
platform=$1
version=$2
binary=$3
case "$platform" in
    x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin) ;;
    *) printf '%s\n' 'Unsupported release platform' >&2; exit 1 ;;
esac
[ "$("$binary" --version)" = "sandbox ${version#v}" ] || {
    printf '%s\n' 'Tag does not match binary version' >&2
    exit 1
}
bundle="agent-sandbox-${version}-${platform}"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT HUP INT TERM
mkdir -p "$staging/$bundle" dist
git archive HEAD | tar -x -C "$staging/$bundle"
mkdir -p "$staging/$bundle/target/release"
cp "$binary" "$staging/$bundle/target/release/sandbox"
chmod +x "$staging/$bundle/target/release/sandbox"
"$staging/$bundle/target/release/sandbox" --root "$staging/$bundle" allow list >/dev/null
tar -czf "dist/$bundle.tar.gz" -C "$staging" "$bundle"
