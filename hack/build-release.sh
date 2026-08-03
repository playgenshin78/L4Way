#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-beta}"
output_root="${2:-${root}/dist}"
release_name="flux-${version}"
stage="${output_root}/${release_name}"
archive="${output_root}/${release_name}.tar.gz"

if [[ ! "${version}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "version may only contain letters, digits, dots, underscores and hyphens" >&2
  exit 2
fi
if [[ -e "${stage}" || -e "${archive}" ]]; then
  echo "release output already exists: ${release_name}" >&2
  exit 2
fi

command -v go >/dev/null
command -v node >/dev/null
command -v corepack >/dev/null
command -v sha256sum >/dev/null
command -v tar >/dev/null

node -e 'const major=Number(process.versions.node.split(".")[0]); if (major < 20) { throw new Error("Node.js 20 or newer is required") }'

mkdir -p "${stage}/bin" "${stage}/web" "${stage}/deploy" "${stage}/examples"

cd "${root}"
go test ./...
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath \
    -ldflags="-s -w -X main.controllerVersion=${version} -X flux.local/flux/internal/control.AgentVersion=${version}" \
    -o "${stage}/bin/flux-controller-linux-${arch}" ./cmd/flux-controller
  CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath \
    -ldflags="-s -w -X flux.local/flux/internal/control.AgentVersion=${version}" \
    -o "${stage}/bin/flux-agent-linux-${arch}" ./cmd/flux-agent
done

cd "${root}/web"
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm build
cp -a dist/. "${stage}/web/"

cd "${root}"
cp -a deploy/. "${stage}/deploy/"
cp -a examples/. "${stage}/examples/"
install -m 0755 install.sh "${stage}/install.sh"
install -m 0755 install.sh "${output_root}/install.sh"
cp PROJECT.md "${stage}/PROJECT.md"
printf '%s\n' "${version}" >"${stage}/VERSION"
(
  cd "${stage}"
  find bin -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
tar -C "${output_root}" -czf "${archive}" "${release_name}"
(
  cd "${output_root}"
  sha256sum "${release_name}.tar.gz" > "${release_name}.tar.gz.sha256"
)

echo "release directory: ${stage}"
echo "release archive: ${archive}"
