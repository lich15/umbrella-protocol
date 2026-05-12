#!/usr/bin/env bash
set -euo pipefail

generated_root="${1:-target/production-readiness/uniffi-generated}"

if [[ ! -d "$generated_root" ]]; then
  echo "generated API directory not found: $generated_root" >&2
  exit 1
fi

if ! rg -n "CloudChatHandle" "$generated_root" >/dev/null; then
  echo "CloudChatHandle missing from generated API" >&2
  exit 1
fi

if ! rg -n "SecretChatHandle" "$generated_root" >/dev/null; then
  echo "SecretChatHandle missing from generated API" >&2
  exit 1
fi

while IFS= read -r file; do
  if awk '
    /SecretChatHandleProtocol|SecretChatHandleInterface|open class SecretChatHandle|class SecretChatHandle/ {
      in_secret = 1
    }
    /FfiConverterTypeSecretChatHandle|UmbrellaClientHandleProtocol|UmbrellaClientHandleInterface|open class UmbrellaClientHandle|class UmbrellaClientHandle/ {
      in_secret = 0
    }
    in_secret && /cloudSyncHistory|cloud_sync_history|CloudSyncHistory|addBot|add_bot|bot/ {
      print FILENAME ":" FNR ":" $0
      bad = 1
    }
    END { exit bad }
  ' "$file"; then
    true
  else
    echo "forbidden cloud-only method on SecretChatHandle: $file" >&2
    exit 1
  fi
done < <(rg -l "SecretChatHandle" "$generated_root")

if rg -n "mode:[[:space:]]*(String|ChatMode)|mode: String|mode: ChatMode|var mode|fun setMode|set_mode" "$generated_root"; then
  echo "mutable chat mode surface detected" >&2
  exit 1
fi
