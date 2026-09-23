#!/usr/bin/env bash
# Catalyst 8000v IPsec VTI + eBGP lab controller (libvirt/KVM): hub, spoke1, spoke2
set -euo pipefail
source "$(dirname "$(readlink -f "$0")")/lab.conf"

# Re-exec under the libvirt group if this login session doesn't have it yet.
if ! id -nG | tr ' ' '\n' | grep -qx libvirt && getent group libvirt | grep -qw "$USER"; then
  exec sg libvirt -c "$(printf '%q ' "$0" "$@")"
fi

V() { virsh -q -c "$LIBVIRT_URI" "$@"; }
die() { echo "error: $*" >&2; exit 1; }
node_dir() { echo "$LAB_DIR/nodes/$1"; }
defined() { V dominfo "$1" &>/dev/null; }
running() { [[ "$(V domstate "$1" 2>/dev/null)" == "running" ]]; }
nodes_or_all() { [[ $# -gt 0 ]] && echo "$*" || echo "${ALL_NODES[*]}"; }

# ---- networks -------------------------------------------------------------
ensure_networks() {
  local n
  for n in "$OOB_NET" ${INTERNET_NET:-}; do
    if ! V net-info "$n" &>/dev/null; then
      V net-define "$LAB_DIR/networks/$n.xml"
      V net-autostart "$n" >/dev/null
    fi
    [[ "$(V net-info "$n" | awk '/Active/{print $2}')" == "yes" ]] || V net-start "$n"
  done
}

# ---- point-to-point WAN links (UDP tunnels between VMs) --------------------
port_local() { echo $(( UDP_BASE + NODE_IDX[$1]*100 + $2 )); }           # UDP port a node's NIC listens on when it anchors a link
port_far()   { echo $(( UDP_BASE + 10000 + NODE_IDX[$1]*100 + $2 )); }   # ...and the port it sends to (the other end listens there)
node_ports() { case "${ROLE[$1]}" in hub) seq 2 $((1 + HUB_PORTS));; firewall) seq 1 "$FW_PORTS";; host) seq 1 "$HOST_PORTS";; *) seq 2 $((1 + SPOKE_PORTS));; esac; }
is_fw()      { [[ "${ROLE[$1]}" == "firewall" ]]; }
is_host()    { [[ "${ROLE[$1]}" == "host" ]]; }
lan_port()   { case "${ROLE[$1]}" in hub) echo "$HUB_LAN_PORT";; firewall|host) ;; *) echo "$SPOKE_LAN_PORT";; esac; }   # a router's site LAN port (spoke, dci, partner: the last port)
port_name()  { if is_fw "$1" || is_host "$1"; then echo "eth$2"; else echo "GigabitEthernet$2"; fi; }
mac()        { printf '%s:%02x:%02x' "$MAC_OUI" "${NODE_IDX[$1]}" "$2"; }
link_peer() {   # node port -> "peer_node peer_port prefix end(1|2)" or "" if unwired
  local me="$1:$2" l a b pfx
  for l in "${LINKS[@]}"; do
    read -r a b pfx <<<"$l"
    [[ "$a" == "$me" ]] && { echo "${b%%:*} ${b##*:} $pfx 1"; return; }
    [[ "$b" == "$me" ]] && { echo "${a%%:*} ${a##*:} $pfx 2"; return; }
  done
  return 0
}
wan_ip() {      # node port -> address on that link (.1 for the first end, .2 for the second)
  local peer; peer="$(link_peer "$1" "$2")"; [[ -z "$peer" ]] && return
  read -r _ _ pfx end <<<"$peer"
  python3 -c "import ipaddress,sys; n=ipaddress.IPv4Network('$pfx'); print(list(n.hosts())[int('$end')-1])"
}

# ---- XML generation -------------------------------------------------------
serial_xml() {
  cat <<X
    <serial type='tcp'>
      <source mode='bind' host='127.0.0.1' service='${CONSOLE_PORT[$1]}'/>
      <protocol type='raw'/>
      <log file='$(node_dir "$1")/console.log' append='on'/>
      <target port='0'/>
    </serial>
X
}

no_offload_xml() {   # IOS-XE's TCP stack rejects partially-checksummed segments from the host tap
  cat <<X
      <driver name='qemu'>
        <host csum='off' gso='off' tso4='off' tso6='off' ecn='off' ufo='off'/>
        <guest csum='off' tso4='off' tso6='off' ecn='off' ufo='off'/>
      </driver>
X
}

router_xml() {     # Gi1 = OOB mgmt; Gi2.. = point-to-point WAN links (UDP tunnels, black-holed when unwired)
  local n="$1" i="${NODE_IDX[$1]}" d; d="$(node_dir "$n")"
  cat <<X
<domain type='kvm'>
  <name>$n</name>
  <uuid>$(uuidgen --sha1 --namespace @dns --name "cat8000v-ipsec.${MGMT_IP[$n]}")</uuid>
  <title>Catalyst 8000v ${ROLE[$n]} ($n)</title>
  <memory unit='MiB'>$C8000V_RAM_MIB</memory>
  <vcpu placement='static'>$C8000V_VCPU</vcpu>
  <cpu mode='host-passthrough' check='none'/>
  <os><type arch='x86_64' machine='pc'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>restart</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$d/disk.qcow2'/>
      <target dev='hda' bus='ide'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='$d/config.iso'/>
      <target dev='hdc' bus='ide'/>
      <readonly/>
    </disk>
    <!-- GigabitEthernet1: OOB management ${MGMT_IP[$n]} (Mgmt-vrf) -->
    <interface type='network'>
      <mac address='$(mac "$n" 1)'/>
      <source network='$OOB_NET'/>
      <model type='virtio'/>
$(no_offload_xml)
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
X
  local p peer remote local
  for p in $(node_ports "$n"); do
    peer="$(link_peer "$n" "$p")"
    # the first end of a link (the hub) always listens on port_local/sends to port_far - wired or not - so the
    # hub's XML never changes when spokes are added; the second end mirrors that pair
    local="$(port_local "$n" "$p")"; remote="$(port_far "$n" "$p")"
    if [[ -n "$peer" ]]; then
      read -r pn pp pfx end <<<"$peer"
      [[ "$end" == "2" ]] && { local="$(port_far "$pn" "$pp")"; remote="$(port_local "$pn" "$pp")"; }
      echo "    <!-- GigabitEthernet$p: $(wan_ip "$n" "$p") <-> $pn $(port_name "$pn" "$pp") ($pfx) -->"
    else
      echo "    <!-- GigabitEthernet$p: unwired -->"
    fi
    cat <<X
    <interface type='udp'>
      <mac address='$(mac "$n" "$p")'/>
      <source address='127.0.0.1' port='$remote'>
        <local address='127.0.0.1' port='$local'/>
      </source>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='$(printf '0x%02x' $((2+p)))' function='0x0'/>
    </interface>
X
  done
  serial_xml "$n"
  cat <<X
    <memballoon model='none'/>
  </devices>
</domain>
X
}

firewall_xml() {   # VyOS: virtio disk, eth0 = OOB mgmt, eth1 = headend side, eth2.. = spokes (same UDP anchoring as routers)
  local n="$1" d; d="$(node_dir "$n")"
  cat <<X
<domain type='kvm'>
  <name>$n</name>
  <uuid>$(uuidgen --sha1 --namespace @dns --name "cat8000v-ipsec.${MGMT_IP[$n]}")</uuid>
  <title>VyOS firewall ($n)</title>
  <memory unit='MiB'>$VYOS_RAM_MIB</memory>
  <vcpu placement='static'>$VYOS_VCPU</vcpu>
  <cpu mode='host-passthrough' check='none'/>
  <os><type arch='x86_64' machine='pc'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>restart</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$d/disk.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <!-- eth0: OOB management ${MGMT_IP[$n]} -->
    <interface type='network'>
      <mac address='$(mac "$n" 0)'/>
      <source network='$OOB_NET'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
X
  local p peer remote local
  for p in $(node_ports "$n"); do
    peer="$(link_peer "$n" "$p")"; local="$(port_local "$n" "$p")"; remote="$(port_far "$n" "$p")"
    if [[ -n "$peer" ]]; then
      read -r pn pp pfx end <<<"$peer"
      [[ "$end" == "2" ]] && { local="$(port_far "$pn" "$pp")"; remote="$(port_local "$pn" "$pp")"; }
      echo "    <!-- eth$p: $(wan_ip "$n" "$p") <-> $pn $(port_name "$pn" "$pp") ($pfx) -->"
    else
      echo "    <!-- eth$p: unwired -->"
    fi
    cat <<X
    <interface type='udp'>
      <mac address='$(mac "$n" "$p")'/>
      <source address='127.0.0.1' port='$remote'>
        <local address='127.0.0.1' port='$local'/>
      </source>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='$(printf '0x%02x' $((3+p)))' function='0x0'/>
    </interface>
X
  done
  if [[ -n "${FW_INTERNET_PORT:-}" ]]; then cat <<X
    <!-- eth$FW_INTERNET_PORT: internet uplink on the libvirt NAT network '$INTERNET_NET' (DHCP; NAT for the site LANs) -->
    <interface type='network'>
      <mac address='$(mac "$n" "$FW_INTERNET_PORT")'/>
      <source network='$INTERNET_NET'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='$(printf '0x%02x' $((3+FW_INTERNET_PORT)))' function='0x0'/>
    </interface>
X
  fi
  serial_xml "$n"
  cat <<X
    <memballoon model='none'/>
  </devices>
</domain>
X
}

# ---- build ------------------------------------------------------------------
host_xml() {       # Alpine LAN host: eth0 = OOB, eth1 = UDP tunnel to its router's LAN port; cloud-init NoCloud seed on a cdrom
  local n="$1" d peer pn pp pfx; d="$(node_dir "$n")"
  peer="$(link_peer "$n" 1)"; read -r pn pp pfx _ <<<"$peer"
  cat <<X
<domain type='kvm'>
  <name>$n</name>
  <uuid>$(uuidgen --sha1 --namespace @dns --name "cat8000v-ipsec.${MGMT_IP[$n]}")</uuid>
  <title>Alpine LAN host ($n, behind $pn)</title>
  <memory unit='MiB'>$HOST_RAM_MIB</memory>
  <vcpu placement='static'>$HOST_VCPU</vcpu>
  <cpu mode='host-passthrough' check='none'/>
  <os><type arch='x86_64' machine='pc'>hvm</type><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>restart</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='$d/disk.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='$d/seed.iso'/>
      <target dev='hda' bus='ide'/>
      <readonly/>
    </disk>
    <!-- eth0: OOB management ${MGMT_IP[$n]} -->
    <interface type='network'>
      <mac address='$(mac "$n" 0)'/>
      <source network='$OOB_NET'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x03' function='0x0'/>
    </interface>
    <!-- eth1: $(wan_ip "$n" 1) <-> $pn $(port_name "$pn" "$pp") ($pfx); the router anchors the socket pair -->
    <interface type='udp'>
      <mac address='$(mac "$n" 1)'/>
      <source address='127.0.0.1' port='$(port_local "$pn" "$pp")'>
        <local address='127.0.0.1' port='$(port_far "$pn" "$pp")'/>
      </source>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </interface>
X
  serial_xml "$n"
  cat <<X
    <memballoon model='none'/>
  </devices>
</domain>
X
}

host_resolver() {   # "<server> <domain>" from the host's dns_client in lab-intent.json, empty when it has none
  "$LAB_DIR/tests/.venv/bin/python" -c '
import json, sys
I = json.load(open(sys.argv[1]))
c = (next((d for d in I["devices"] if d["name"] == sys.argv[2]), {}) or {}).get("dns_client") or {}
print(c.get("server", ""), c.get("domain", ""))' "$LAB_DIR/lab-intent.json" "$1"
}
host_seed() {      # cloud-init NoCloud seed: static addresses (network-config v2 by MAC), user lab / lab, sshd, node-exporter
  local n="$1" d peer pn pp pfx cidr gw ns; d="$(node_dir "$n")"
  peer="$(link_peer "$n" 1)"; [[ -n "$peer" ]] || die "$n eth1 is not wired in LINKS"; read -r pn pp pfx _ <<<"$peer"
  cidr="$(wan_ip "$n" 1)/${pfx##*/}"; gw="$(wan_ip "$pn" "$pp")"
  ns="$(host_resolver "$n")"   # a host may resolve through a server on the far side of the DCI (intent: the host's dns_client)
  echo "[$n] building cloud-init (NoCloud) seed ISO"
  cat > "$d/network-config" <<U
version: 2
ethernets:
  oob:
    match: { macaddress: "$(mac "$n" 0)" }
    set-name: eth0
    addresses: [${MGMT_IP[$n]}/24]
    routes: [{ to: 10.0.0.0/8, via: $OOB_GATEWAY }]
  lan:
    match: { macaddress: "$(mac "$n" 1)" }
    set-name: eth1
    addresses: [$cidr]
    routes: [{ to: 0.0.0.0/0, via: $gw }]$([[ -n "${ns% *}" ]] && printf '\n    nameservers: { addresses: [%s], search: [%s] }' "${ns%% *}" "${ns##* }")
U
  cat > "$d/user-data" <<U
#cloud-config
# $n: eth0 = OOB management (${MGMT_IP[$n]}), eth1 = LAN behind $pn $(port_name "$pn" "$pp") ($pfx, gateway $gw)
hostname: $n
users:
  - name: lab
    plain_text_passwd: lab
    lock_passwd: false
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/sh
ssh_pwauth: true
write_files:
  - path: /etc/motd
    content: "$n — LAN host behind $pn: eth1 $cidr (gateway $gw), OOB eth0 ${MGMT_IP[$n]}. iperf3 / tcpdump / mtr installed.\n"$([[ -n "${ns% *}" ]] && printf '\n  - path: /etc/resolv.conf.head\n    content: "# resolver from lab-intent.json (dns_client): a server on the far side of the DCI\\nsearch %s\\nnameserver %s\\n"' "${ns##* }" "${ns%% *}")
runcmd:$([[ -n "${ns% *}" ]] && printf '\n  - printf "search %s\\nnameserver %s\\n" > /etc/resolv.conf' "${ns##* }" "${ns%% *}")
  - rc-update add sshd default
  - rc-service sshd restart
  - rc-update add node-exporter default
  - rc-service node-exporter restart
U
  printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$n" "$(cat "$d/network-config" "$d/user-data" | md5sum | cut -c1-8)" "$n" > "$d/meta-data"
  genisoimage -quiet -o "$d/seed.iso.tmp" -V cidata -J -r "$d/user-data" "$d/meta-data" "$d/network-config" && mv -f "$d/seed.iso.tmp" "$d/seed.iso"
}

build_host() {
  local n="$1" d; d="$(node_dir "$n")"
  [[ -f "$HOST_IMAGE" ]] || die "host base image not found: $HOST_IMAGE (built by srv6-core/tools/build_host_image.sh)"
  mkdir -p "$d"
  if [[ ! -f "$d/disk.qcow2" ]]; then
    echo "[$n] creating overlay disk on $(basename "$HOST_IMAGE")"
    qemu-img create -q -f qcow2 -b "$HOST_IMAGE" -F qcow2 "$d/disk.qcow2"
  fi
  host_seed "$n"
  host_xml "$n" > "$d/domain.xml"
  V define "$d/domain.xml" >/dev/null
}

build_firewall() {
  local n="$1" d; d="$(node_dir "$n")"; mkdir -p "$d"
  [[ -f "$VYOS_IMAGE" ]] || die "VyOS base image not found: $VYOS_IMAGE (see tools/vyos_install.py)"
  if [[ ! -f "$d/disk.qcow2" ]]; then
    echo "[$n] creating overlay disk on $(basename "$VYOS_IMAGE")"
    qemu-img create -q -f qcow2 -b "$VYOS_IMAGE" -F qcow2 "$d/disk.qcow2"
  fi
  firewall_xml "$n" > "$d/domain.xml"
  V define "$d/domain.xml" >/dev/null
}

build_router() {
  if is_fw "$1"; then build_firewall "$1"; return; fi
  if is_host "$1"; then build_host "$1"; return; fi
  local n="$1" d; d="$(node_dir "$n")"; mkdir -p "$d"
  [[ -f "$C8000V_IMAGE" ]] || die "base image not found: $C8000V_IMAGE"
  # a router added to lab.conf by hand has no day-0 config yet (the portal writes one when it provisions a spoke): render the template
  if [[ ! -f "$d/iosxe_config.txt" ]]; then
    echo "[$n] writing day-0 config from the template"
    sed -e "s/__HOSTNAME__/$n/" -e "s/__MGMT_IP__/${MGMT_IP[$n]}/" -e "s/__GATEWAY__/$OOB_GATEWAY/" "$LAB_DIR/nodes/_template/spoke.iosxe_config.txt" > "$d/iosxe_config.txt"
    cp -f "$LAB_DIR/nodes/_template/spoke.post-boot.txt" "$d/post-boot.txt"
  fi
  if [[ ! -f "$d/disk.qcow2" ]]; then
    echo "[$n] creating overlay disk on $(basename "$C8000V_IMAGE")"
    qemu-img create -q -f qcow2 -b "$C8000V_IMAGE" -F qcow2 "$d/disk.qcow2"
  fi
  echo "[$n] building day-0 config ISO"
  # temp file + rename: libvirt chowns the previous ISO to libvirt-qemu
  genisoimage -quiet -o "$d/config.iso.tmp" -l -J -r -V config "$d/iosxe_config.txt" && mv -f "$d/config.iso.tmp" "$d/config.iso"
  router_xml "$n" > "$d/domain.xml"
  V define "$d/domain.xml" >/dev/null
}

save_config() {   # write memory: RESTCONF RPC first, serial console as fallback
  local n="$1" user="${IOSXE_USERNAME:-admin}" pass="${IOSXE_PASSWORD:-admin}"
  curl -sk -u "$user:$pass" -m 30 -X POST "https://${MGMT_IP[$n]}/restconf/operations/cisco-ia:save-config" \
       -H 'Content-Type: application/yang-data+json' -H 'Accept: application/yang-data+json' 2>/dev/null | grep -qi success && return 0
  timeout 90 python3 "$LAB_DIR/tools/console.py" send 127.0.0.1 "${CONSOLE_PORT[$n]}" "write memory" >/dev/null 2>&1
}

restconf_ready() { [[ "$(curl -sk -u "${IOSXE_USERNAME:-admin}:${IOSXE_PASSWORD:-admin}" -m 8 -o /dev/null -w '%{http_code}' \
                     "https://${MGMT_IP[$1]}/restconf/data/Cisco-IOS-XE-native:native/hostname" -H 'Accept: application/yang-data+json' 2>/dev/null)" == "200" ]]; }

# ---- commands ---------------------------------------------------------------
cmd_up() {
  ensure_networks
  for n in $(nodes_or_all "$@"); do
    defined "$n" || build_router "$n"
    # pre-create the console log so virtlogd appends to our file instead of a root-only one
    [[ -f "$(node_dir "$n")/console.log" ]] || { touch "$(node_dir "$n")/console.log"; chmod 644 "$(node_dir "$n")/console.log"; }
    if running "$n"; then echo "[$n] already running"; else V start "$n"; echo "[$n] started (console: 127.0.0.1:${CONSOLE_PORT[$n]})"; fi
  done
}

cmd_down() {
  for n in $(nodes_or_all "$@"); do
    running "$n" || { echo "[$n] not running"; continue; }
    if is_fw "$n" || is_host "$n"; then V shutdown "$n" >/dev/null; for _ in $(seq 20); do running "$n" || break; sleep 2; done; running "$n" && V destroy "$n" >/dev/null; echo "[$n] stopped"; continue; fi
    echo "[$n] saving config, then powering off"
    save_config "$n" || echo "[$n] warning: could not save config"
    V destroy "$n" >/dev/null; echo "[$n] stopped"
  done
}

cmd_rebuild() {    # re-define domains from lab.conf/templates without touching disks
  for n in $(nodes_or_all "$@"); do
    running "$n" && die "$n is running; stop it first"
    defined "$n" && V undefine "$n" >/dev/null
    build_router "$n"; echo "[$n] redefined"
  done
}

cmd_clean() {      # destroy VMs and delete overlay disks (base image untouched)
  for n in $(nodes_or_all "$@"); do
    running "$n" && V destroy "$n" >/dev/null
    defined "$n" && V undefine "$n" >/dev/null
    rm -f "$(node_dir "$n")"/{disk.qcow2,config.iso,seed.iso,meta-data,user-data,network-config,domain.xml,console.log}
    echo "[$n] removed"
  done
}

cmd_status() {
  printf '%-15s %-8s %-10s %-10s %-6s %-16s %-8s\n' NODE ROLE STATE MGMT-IP AS LAN CONSOLE
  for n in "${ALL_NODES[@]}"; do
    local lan="${LAN[$n]}"; is_host "$n" && lan="$(wan_ip "$n" 1) (LAN of $(link_peer "$n" 1 | cut -d' ' -f1))"
    printf '%-15s %-8s %-10s %-10s %-6s %-16s %-8s\n' "$n" "${ROLE[$n]}" "$(V domstate "$n" 2>/dev/null || echo undefined)" \
      "${MGMT_IP[$n]}" "${BGP_AS[$n]}" "$lan" "${CONSOLE_PORT[$n]}"
  done
  echo; echo "WAN links (point-to-point) and IPsec VTI tunnels:"
  local l a b pfx t; for l in "${LINKS[@]}"; do read -r a b pfx <<<"$l"; echo "  ${a%%:*} $(port_name "${a%%:*}" "${a##*:}") $(wan_ip "${a%%:*}" "${a##*:}")  <->  ${b%%:*} $(port_name "${b%%:*}" "${b##*:}") $(wan_ip "${b%%:*}" "${b##*:}")   ($pfx)"; done
  for t in "${TUNNELS[@]}"; do read -r id hb sp pfx <<<"$t"; echo "  Tunnel$id: $hb <-> $sp  $pfx  (ipsec ipv4, IKEv2 PSK, eBGP)"; done
}

cmd_console() {
  local n="${1:?node}"; running "$n" || die "$n is not running"
  echo "Connecting to $n console (exit: Ctrl-] then q)"; echo
  socat -,raw,echo=0,escape=0x1d "tcp:127.0.0.1:${CONSOLE_PORT[$n]}"
}

cmd_ssh() {
  local n="${1:?node}"; shift || true
  if is_host "$n"; then echo "(host: user lab, password lab)" >&2; ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PubkeyAuthentication=no "lab@${MGMT_IP[$n]}" "$@"; return; fi
  if is_fw "$n"; then ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "vyos@${MGMT_IP[$n]}" "$@"; return; fi
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "admin@${MGMT_IP[$n]}" "$@"
}

fw_ready() { timeout 8 bash -c "exec 3<>/dev/tcp/${MGMT_IP[$1]}/22" 2>/dev/null; }
bootstrap_firewall() {   # VyOS day-0 over the serial console: hostname, eth0, ssh, LLDP (nodes/<fw>/vyos_config.txt)
  local n="$1" d; d="$(node_dir "$n")"
  echo "[$n] waiting for the VyOS login prompt..."
  python3 "$LAB_DIR/tools/vyos_console.py" wait 127.0.0.1 "${CONSOLE_PORT[$n]}" 600 >/dev/null
  echo "[$n] applying day-0 config"
  python3 "$LAB_DIR/tools/vyos_console.py" push 127.0.0.1 "${CONSOLE_PORT[$n]}" "$d/vyos_config.txt" >/dev/null
  for _ in $(seq 30); do fw_ready "$n" && break; sleep 5; done
  fw_ready "$n" && echo "[$n] ready: ssh vyos@${MGMT_IP[$n]} (vyos)" || echo "[$n] warning: SSH not answering yet"
}

cmd_bootstrap() {  # wait for boot, (re)apply day-0, generate SSH keys; then wait for RESTCONF
  for n in $(nodes_or_all "$@"); do
    if is_fw "$n"; then bootstrap_firewall "$n"; continue; fi
    if is_host "$n"; then for _ in $(seq 60); do fw_ready "$n" && break; sleep 5; done; fw_ready "$n" && echo "[$n] ready: ssh lab@${MGMT_IP[$n]} (lab)" || echo "[$n] warning: SSH not answering yet"; continue; fi
    local d; d="$(node_dir "$n")"
    echo "[$n] waiting for console prompt (C8000v takes ~3-5 min on first boot)..."
    python3 "$LAB_DIR/tools/console.py" wait 127.0.0.1 "${CONSOLE_PORT[$n]}" 1800 >/dev/null
    echo "[$n] applying config + generating SSH keys"
    python3 "$LAB_DIR/tools/console.py" push 127.0.0.1 "${CONSOLE_PORT[$n]}" "$d/iosxe_config.txt" >/dev/null
    python3 "$LAB_DIR/tools/console.py" push 127.0.0.1 "${CONSOLE_PORT[$n]}" "$d/post-boot.txt" >/dev/null
    # the crypto feature set needs the license boot level, which only takes effect after a reload
    if ! python3 "$LAB_DIR/tools/console.py" send 127.0.0.1 "${CONSOLE_PORT[$n]}" "show version | include ^License Level" 2>/dev/null | grep -q 'network-advantage'; then
      echo "[$n] license boot level not active yet: reloading once"
      python3 - "${CONSOLE_PORT[$n]}" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1]))); s.settimeout(2)
for cmd in ("\r", "write memory\r", "reload\r", "\r", "\r"):
    s.sendall(cmd.encode()); time.sleep(4)
    try: s.recv(65536)
    except socket.timeout: pass
s.close()
PY
      sleep 60
      python3 "$LAB_DIR/tools/console.py" wait 127.0.0.1 "${CONSOLE_PORT[$n]}" 1800 >/dev/null
    fi
    for _ in $(seq 60); do restconf_ready "$n" && break; sleep 10; done
    restconf_ready "$n" && echo "[$n] ready: ssh admin@${MGMT_IP[$n]} (admin), RESTCONF up" || echo "[$n] warning: RESTCONF not answering yet"
  done
}

cmd_wait() {       # block until RESTCONF (routers) / SSH (firewalls) answers on the given nodes (used after up)
  for n in $(nodes_or_all "$@"); do
    if is_fw "$n" || is_host "$n"; then for _ in $(seq 60); do fw_ready "$n" && break; sleep 5; done; fw_ready "$n" && echo "[$n] SSH ready" || echo "[$n] SSH NOT ready"; continue; fi
    for _ in $(seq 90); do restconf_ready "$n" && break; sleep 10; done
    restconf_ready "$n" && echo "[$n] RESTCONF ready" || echo "[$n] RESTCONF NOT ready"
  done
}

cmd_log() { tail -n "${2:-50}" -f "$(node_dir "${1:?node}")/console.log"; }

cmd_nac() {        # run terraform in nac/ with router credentials in the environment
  export PATH="$HOME/.local/bin:$PATH"
  command -v terraform >/dev/null || die "terraform not found in PATH"
  local user="${IOSXE_USERNAME:-admin}" pass="${IOSXE_PASSWORD:-admin}"
  cd "$LAB_DIR/nac"
  IOSXE_USERNAME="$user" IOSXE_PASSWORD="$pass" terraform "$@"
  local rc=$?
  if [[ $rc -eq 0 && "${1:-}" == "apply" ]]; then
    for n in "${ROUTERS[@]}"; do is_fw "$n" && continue; save_config "$n" && echo "[$n] running-config saved to startup-config" || echo "[$n] warning: save failed" >&2; done
  fi
  return $rc
}

# ---- Nautobot (shared NMS of the cat9000v lab: http://10.0.0.10:8080) ----------------
NAUTOBOT_URL="${NAUTOBOT_URL:-http://10.0.0.10:8080}"
nautobot_token() { ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR lab@10.0.0.10 'grep ^NAUTOBOT_SUPERUSER_API_TOKEN /opt/nautobot/.env | cut -d= -f2'; }
nautobot_py() {
  [[ -x "$LAB_DIR/tests/.venv/bin/python" ]] || "$LAB_DIR/tests/setup.sh"
  NAUTOBOT_URL="$NAUTOBOT_URL" NAUTOBOT_TOKEN="$(nautobot_token)" "$LAB_DIR/tests/.venv/bin/python" "$LAB_DIR/nautobot/$1" "${@:2}"
}
cmd_nautobot() {
  local sub="${1:-render}"; shift || true
  case "$sub" in
    onboard) nautobot_py onboard.py "$@" ;;        # discover r1-r3 (Sync Devices From Network)
    seed)    nautobot_py seed.py "$@" ;;           # load the DMVPN intent (idempotent)
    render)  nautobot_py render_nac.py "$@" ;;     # regenerate nac/data/devices.nac.yaml (--check to verify)
    vyos)    nautobot_py render_vyos.py "$@" ;;      # render + push the VyOS firewalls from Nautobot (--check | --dry-run)
    pki)     nautobot_py pki.py "$@" ;;              # certificate enrolment of the routers against pki/ca.py (--check | --force | --post-apply [device ...])
    golden)  GITEA_PASSWORD="$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR lab@10.0.0.10 'grep ^GITEA_PASSWORD /opt/nautobot/.env | cut -d= -f2')" \
             nautobot_py golden_config.py "$@" ;;  # Golden Config scope/template for the routers + backup/intended/compliance
    token)   nautobot_token ;;
    *) die "usage: lab.sh nautobot {onboard|seed|render [--check]|vyos [--check|--dry-run]|golden|token}" ;;
  esac
}

cmd_intent() {     # lab-intent.json: init (from lab.conf) | validate | show
  python3 "$LAB_DIR/nautobot/intent.py" "$@"
}

cmd_rename() {     # rename a (stopped) router everywhere: ./lab.sh rename OLD NEW
  python3 "$LAB_DIR/nautobot/rename_node.py" "$@"
}

cmd_webapp() {     # VPN provisioning portal (FastAPI/uvicorn) on http://0.0.0.0:8090
  [[ -x "$LAB_DIR/webapp/.venv/bin/uvicorn" ]] || "$LAB_DIR/webapp/setup.sh"
  [[ -f "$LAB_DIR/lab-intent.json" ]] || python3 "$LAB_DIR/nautobot/intent.py" init
  export PATH="$HOME/.local/bin:$PATH"
  cd "$LAB_DIR/webapp" && exec .venv/bin/uvicorn app:app --host "${WEBAPP_HOST:-0.0.0.0}" --port "${WEBAPP_PORT:-8090}" "$@"
}

cmd_hosts() {      # the LAN hosts: `hosts` = ping matrix (every host to every other host over the tunnels), `hosts run NAME CMD`
  [[ -x "$LAB_DIR/tests/.venv/bin/python" ]] || "$LAB_DIR/tests/setup.sh"
  "$LAB_DIR/tests/.venv/bin/python" "$LAB_DIR/tools/host_cmd.py" "${1:-matrix}" "${@:2}"
}

cmd_test() {       # Robot Framework suite; results in results/<date>_<time>/
  [[ -x "$LAB_DIR/tests/.venv/bin/robot" ]] || "$LAB_DIR/tests/setup.sh"
  exec "$LAB_DIR/tests/run.sh" "$@"
}

usage() {
  cat <<U
usage: $(basename "$0") <command> [node...]
  up [node..]        create (if needed) and start nodes          (default: all)
  down [node..]      save configs and stop nodes                 (default: all)
  status             show nodes, addresses, console ports
  console <node>     attach to serial console
  ssh <node> [cmd]   ssh to a node's OOB management IP (routers admin/admin, firewalls vyos/vyos, hosts lab/lab)
  hosts [run N CMD]  ping matrix between the LAN hosts (or run a command on one host)
  bootstrap [node..] wait for boot, generate SSH keys, wait for RESTCONF (first boot)
  wait [node..]      wait until RESTCONF answers
  log <node> [n]     follow a node's console log
  nac <tf args..>    run terraform in nac/ (init | plan | apply)
  test [robot args]  run the Robot Framework tests
  intent <cmd>       init|validate|show  lab-intent.json (the document the web app edits)
  webapp             start the VPN provisioning portal on http://<host>:8090
  rename OLD NEW     rename a stopped router (VM, lab.conf, intent, terraform state); then rebuild/up + nautobot seed
  nautobot <cmd>     onboard|seed|render|vyos|pki|golden|token  (shared Nautobot at $NAUTOBOT_URL)
  rebuild [node..]   re-generate domain XML / day-0 ISO (keeps disks)
  clean [node..]     stop, undefine and delete overlay disks
nodes: ${ALL_NODES[*]}
U
}

cmd="${1:-}"; shift || true
case "$cmd" in
  up|down|status|console|ssh|bootstrap|wait|log|nac|nautobot|test|intent|webapp|rename|rebuild|clean|hosts) "cmd_$cmd" "$@" ;;
  *) usage; exit 1 ;;
esac
