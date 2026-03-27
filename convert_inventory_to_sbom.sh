#!/usr/bin/env bash

set -euo pipefail

declare -r INVENTORY_FILE="${INVENTORY_FILE:-/.bottlerocket/host-containers/current/inventory/application-inventory.json}"
declare -r OUTPUT_FILE="${OUTPUT_FILE:-/tmp/bottlerocket-sbom.json}"
declare -r IMDS_ENDPOINT="http://169.254.169.254"
declare -r IMDS_TOKEN_TTL="21600"

log() {
  echo "$*" >&2
}

# Get IMDSv2 token
get_imds_token() {
  curl -sf -X PUT "${IMDS_ENDPOINT}/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: ${IMDS_TOKEN_TTL}" 2>/dev/null || echo ""
}

# Fetch IMDS metadata with token
imds_get() {
  local path="$1"
  local token="$2"
  if [[ -n "${token}" ]]; then
    curl -sf -H "X-aws-ec2-metadata-token: ${token}" "${IMDS_ENDPOINT}${path}" 2>/dev/null || echo ""
  else
    echo ""
  fi
}

# Collect network interface properties as JSON array elements
get_network_properties() {
  local props="[]"
  for iface_path in /sys/class/net/*; do
    local name
    name=$(basename "${iface_path}")
    [[ "${name}" == "lo" ]] && continue

    local mac=""
    [[ -f "${iface_path}/address" ]] && mac=$(cat "${iface_path}/address" 2>/dev/null || echo "")
    local ipv4=""
    ipv4=$(ip -4 addr show "${name}" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1 || echo "")

    if [[ -n "${mac}" ]]; then
      props=$(echo "${props}" | jq --arg n "amazon:inspector:sbom_generator:metadata:host:network_interfaces:${name}:hardware" --arg v "${mac}" '. + [{"name": $n, "value": $v}]')
    fi
    if [[ -n "${ipv4}" ]]; then
      props=$(echo "${props}" | jq --arg n "amazon:inspector:sbom_generator:metadata:host:network_interfaces:${name}:ipv4" --arg v "${ipv4}" '. + [{"name": $n, "value": $v}]')
    fi
  done
  echo "${props}"
}

main() {
  if [[ ! -f "${INVENTORY_FILE}" ]]; then
    log "Inventory file not found: ${INVENTORY_FILE}"
    exit 0
  fi

  log "Converting application inventory to CycloneDX SBOM..."

  # Generate UUID and timestamp
  local uuid
  uuid=$(cat /proc/sys/kernel/random/uuid)
  local timestamp
  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

  # Get IMDS token and metadata
  local token
  token=$(get_imds_token)
  local instance_id
  instance_id=$(imds_get "/latest/meta-data/instance-id" "${token}")
  local instance_type
  instance_type=$(imds_get "/latest/meta-data/instance-type" "${token}")
  local az
  az=$(imds_get "/latest/meta-data/placement/availability-zone" "${token}")
  local region="${az%?}"
  local identity_doc
  identity_doc=$(imds_get "/latest/dynamic/instance-identity/document" "${token}")
  local account_id=""
  if [[ -n "${identity_doc}" ]]; then
    account_id=$(echo "${identity_doc}" | jq -r '.accountId // empty' 2>/dev/null || echo "")
  fi
  local hostname
  hostname=$(imds_get "/latest/meta-data/hostname" "${token}")
  local cpu_arch
  cpu_arch=$(uname -m)

  # Determine partition from region
  local partition="aws"
  if [[ "${region}" == cn-* ]]; then
    partition="aws-cn"
  elif [[ "${region}" == us-gov-* ]]; then
    partition="aws-us-gov"
  fi

  # Host metadata
  local kernel_name
  kernel_name=$(uname -s)
  local kernel_version
  kernel_version=$(uname -r)
  local boot_id=""
  [[ -f /proc/sys/kernel/random/boot_id ]] && boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo "")
  local boot_time=""
  boot_time=$(uptime -s 2>/dev/null | tr ' ' 'T' || echo "")
  [[ -n "${boot_time}" ]] && boot_time="${boot_time}Z"
  local system_id="${instance_id}"
  [[ -f /sys/class/dmi/id/product_uuid ]] && system_id=$(cat /sys/class/dmi/id/product_uuid 2>/dev/null || echo "${instance_id}")

  # Get Bottlerocket version from inventory
  local br_version
  br_version=$(jq -r '.Content[] | select(.Name == "bottlerocket-metadata") | .Version' "${INVENTORY_FILE}" 2>/dev/null || echo "")
  if [[ -z "${br_version}" ]] && [[ -f /.bottlerocket/rootfs/etc/os-release ]]; then
    br_version=$(grep '^VERSION_ID=' /.bottlerocket/rootfs/etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "")
  fi
  [[ -z "${br_version}" ]] && br_version="unknown"

  # Collect network properties
  local net_props
  net_props=$(get_network_properties)

  # Build OS component properties as a temp file
  local props_file
  props_file=$(mktemp)
  jq -n \
    --arg hostname "${hostname}" \
    --arg kernel_name "${kernel_name}" \
    --arg kernel_version "${kernel_version}" \
    --arg cpu_arch "${cpu_arch}" \
    --arg instance_id "${instance_id}" \
    --arg instance_type "${instance_type}" \
    --arg region "${region}" \
    --arg partition "${partition}" \
    --arg account_id "${account_id}" \
    --arg boot_id "${boot_id}" \
    --arg boot_time "${boot_time}" \
    --arg system_id "${system_id}" \
    --argjson net_props "${net_props}" \
    '[
      {"name": "amazon:inspector:sbom_generator:metadata:host:hostname", "value": $hostname},
      {"name": "amazon:inspector:sbom_generator:metadata:host:kernel_name", "value": $kernel_name},
      {"name": "amazon:inspector:sbom_generator:metadata:host:kernel_version", "value": $kernel_version},
      {"name": "amazon:inspector:sbom_generator:metadata:host:cpu_architecture", "value": $cpu_arch},
      {"name": "amazon:inspector:sbom_generator:metadata:imds:provider", "value": "aws"},
      {"name": "amazon:inspector:sbom_generator:metadata:imds:instance_id", "value": $instance_id},
      {"name": "amazon:inspector:sbom_generator:metadata:imds:instance_type", "value": $instance_type},
      {"name": "amazon:inspector:sbom_generator:metadata:imds:instance_location", "value": $region},
      {"name": "amazon:inspector:sbom_generator:metadata:imds:instance_partition", "value": $partition},
      {"name": "amazon:inspector:sbom_generator:metadata:imds:account_id", "value": $account_id},
      {"name": "amazon:inspector:sbom_generator:metadata:imds:resource_type", "value": "ec2:instance"},
      {"name": "amazon:inspector:sbom_generator:metadata:host:boot_id", "value": $boot_id},
      {"name": "amazon:inspector:sbom_generator:metadata:host:boot_time", "value": $boot_time},
      {"name": "amazon:inspector:sbom_generator:metadata:host:system_id", "value": $system_id},
      {"name": "amazon:inspector:sbom_generator:metadata:host:system_serial", "value": $system_id}
    ] + $net_props' > "${props_file}"

  # Build package components to a temp file
  local pkgs_file
  pkgs_file=$(mktemp)
  jq '[
    .Content | to_entries[] |
    .value as $pkg | (.key + 2) as $ref |
    {
      "bom-ref": ("comp-" + ($ref | tostring)),
      "type": "library",
      "name": $pkg.Name,
      "version": ($pkg.Version + "-" + $pkg.Release),
      "purl": (
        "pkg:rpm/bottlerocket/" + $pkg.Name + "@" + $pkg.Version + "-" + $pkg.Release +
        "?arch=" + $pkg.Architecture +
        (if $pkg.Epoch != "0" and $pkg.Epoch != "" then "&epoch=" + $pkg.Epoch else "" end)
      ),
      "publisher": $pkg.Publisher,
      "description": $pkg.Summary
    }
  ]' "${INVENTORY_FILE}" > "${pkgs_file}"

  # Assemble final SBOM from temp files
  jq -n \
    --arg uuid "${uuid}" \
    --arg ts "${timestamp}" \
    --arg br_ver "${br_version}" \
    --slurpfile os_props "${props_file}" \
    --slurpfile pkgs "${pkgs_file}" \
    '{
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "serialNumber": ("urn:uuid:" + $uuid),
      "version": 1,
      "metadata": {
        "timestamp": $ts,
        "tools": {
          "components": [
            {
              "type": "application",
              "author": "Amazon Web Services, Inc. (AWS)",
              "name": "bottlerocket-inventory-to-sbom",
              "version": "1.0.0"
            }
          ]
        }
      },
      "components": ([
        {
          "bom-ref": "comp-1",
          "type": "operating-system",
          "name": "Bottlerocket",
          "version": $br_ver,
          "properties": $os_props[0]
        }
      ] + $pkgs[0])
    }' > "${OUTPUT_FILE}"

  # Clean up temp files
  rm -f "${props_file}" "${pkgs_file}"

  log "SBOM written to ${OUTPUT_FILE}"
}

main
