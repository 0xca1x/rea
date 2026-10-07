#!/usr/bin/env bash
set -euo pipefail

NODE_VERSION="24.18.0"
NODE_SHA256="55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742"
export PATH="/usr/local/bin:${PATH}"

if [[ "$(/usr/local/bin/node -v 2>/dev/null || true)" != "v${NODE_VERSION}" ]]; then
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/node.tar.xz" "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
  echo "${NODE_SHA256}  ${tmp}/node.tar.xz" | sha256sum -c -
  sudo tar -xJf "${tmp}/node.tar.xz" -C /usr/local --strip-components=1
  rm -rf "${tmp}"
fi

hash -r

for cmd in node npm npx corepack; do
  if [[ -x "/usr/local/bin/${cmd}" ]]; then
    sudo ln -sfn "/usr/local/bin/${cmd}" "/usr/local/cargo/bin/${cmd}"
  fi
done

if [[ -f "${HOME}/.bashrc" ]] && ! grep -qF '# rea-dev-node' "${HOME}/.bashrc"; then
  printf '\n# rea-dev-node\nexport PATH="/usr/local/bin:$PATH"\n' >> "${HOME}/.bashrc"
fi

npm ci
