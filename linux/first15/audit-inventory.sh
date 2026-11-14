#!/bin/sh

set -f

# ---- output format -----------------------------------------------------------

format=${1:-both}
case $format in
    table|yaml|both) ;;
    *)
        echo "Usage: $0 [table|yaml|both]" >&2
        exit 1
        ;;
esac

if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [table|yaml|both]" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    case "$0" in -*) ;; *)
        if sudo -n true 2>/dev/null; then exec sudo sh "$0" "$@"; fi ;;
    esac
    echo "WARNING: not root - other users' processes will show as NO-OWNER." >&2
fi

if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
    echo "ERROR: need ss or netstat" >&2
    exit 1
fi

tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT

# ---- helpers -----------------------------------------------------------------

# Prints "<proto> <addr:port> <pid> <name>" for every TCP listener / UDP socket.
list_sockets() {
    if command -v ss >/dev/null 2>&1; then
        ss -lntup 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {
            pid = "-"; name = "-"; r = $0
            # a socket can be shared by several pids (master + workers): keep the lowest = the master
            while (match(r, /\("[^"]*",pid=[0-9]+/)) {
                s = substr(r, RSTART, RLENGTH); r = substr(r, RSTART + RLENGTH)
                split(s, a, "\""); sub(/.*pid=/, "", s)
                if (pid == "-" || s + 0 < pid + 0) { pid = s; name = a[2] }
            }
            print $1, $5, pid, name }'
    else
        netstat -lntup 2>/dev/null | awk '$1 ~ /^(tcp|udp)/ {
            pid = "-"; name = "-"
            if ($NF ~ /^[0-9]+\//) { split($NF, a, "/"); pid = a[1]; name = a[2] }
            print $1, $4, pid, name }'
    fi
}

# Splits address from port, simplifies the address, removes duplicates (IPv4+IPv6).
normalize() {
    awk '{
        proto = toupper(substr($1, 1, 3)); a = $2; port = a
        sub(/.*:/, "", port); sub(/:[^:]*$/, "", a); sub(/%.*/, "", a); gsub(/\[|\]/, "", a)
        if (a == "0.0.0.0" || a == "*" || a == "::" || a == "") b = "all"
        else if (a ~ /^127\./ || a == "::1") b = "local"
        else b = a
        print proto, port, b, $3, $4 }' | sort -u | sort -k2,2n -k1,1
}

is_web_name() {
    case $1 in
        nginx|openresty|apache*|httpd|caddy|lighttpd|traefik|haproxy|php*|node*|deno|bun|\
        gunicorn*|uwsgi*|uvicorn|python*|ruby*|puma|unicorn*|java|tomcat*|jetty|dotnet|flask)
            return 0 ;;
    esac
    return 1
}

# General identifier for a port/protocol (dns, http, ssh...). Empty if unknown.
port_ident() {
    case $1 in
        20|21) echo ftp ;;
        22)    echo ssh ;;
        23)    echo telnet ;;
        25)    echo smtp ;;
        53)    echo dns ;;
        5353)  echo mdns ;;
        67|68) echo dhcp ;;
        80)    echo http ;;
        110)   echo pop3 ;;
        123)   echo ntp ;;
        143)   echo imap ;;
        161)   echo snmp ;;
        389)   echo ldap ;;
        443)   echo https ;;
        445)   echo smb ;;
        465)   echo smtps ;;
        587)   echo smtp-submission ;;
        631)   echo ipp ;;
        636)   echo ldaps ;;
        993)   echo imaps ;;
        995)   echo pop3s ;;
        2049)  echo nfs ;;
        3306)  echo mysql ;;
        3389)  echo rdp ;;
        5432)  echo postgresql ;;
        5672)  echo amqp ;;
        5900)  echo vnc ;;
        6379)  echo redis ;;
        8080)  echo http-alt ;;
        8443)  echo https-alt ;;
        9200)  echo elasticsearch ;;
        11211) echo memcached ;;
        27017) echo mongodb ;;
        *)     getent services "$1/$2" 2>/dev/null | awk '{ print $1; exit }' ;;
    esac
}

# Names the web app / codebase in a directory (or up to 2 parents). $R = process root.
app_type() {
    d=$1; n=0
    while [ "$n" -lt 3 ] && [ -n "$d" ] && [ "$d" != / ]; do
        for m in wp-config.php:WordPress artisan:Laravel manage.py:Django \
                 config/application.rb:Rails bin/magento:Magento configuration.php:Joomla \
                 sites/default/settings.php:Drupal occ:Nextcloud LocalSettings.php:MediaWiki \
                 WEB-INF:Java-webapp package.json:Node composer.json:PHP requirements.txt:Python \
                 app.py:Python wsgi.py:Python Gemfile:Ruby go.mod:Go pom.xml:Java \
                 index.php:PHP index.html:static-HTML; do
            if [ -e "$R$d/${m%%:*}" ]; then echo "${m#*:}"; return; fi
        done
        d=$(dirname "$d"); n=$((n + 1))
    done
}

# ---- header ------------------------------------------------------------------

host=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)
ips=$(hostname -I 2>/dev/null)
[ -n "$ips" ] || ips=$(ip -o -4 addr show scope global 2>/dev/null | awk '{ sub(/\/.*/, "", $4); printf "%s ", $4 }')

if [ "$format" != yaml ]; then
    echo "Host: $host    IP: ${ips:-unknown}    Run as: $(id -un)    $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    printf '%-8s %-15s %-7s %-16s %-14s %-22s %s\n' PORT BIND PID PROCESS USER FLAGS DETAILS
fi

# ---- one row per listening port ----------------------------------------------

list_sockets | normalize | while read -r proto port bind pid name; do
    user="?"; web=no; flags=""; path=""; cfg=""; unit=""; exe=""; roots=""; R=""

    if [ "$pid" != "-" ] && [ -d "/proc/$pid" ]; then
        R=/proc/$pid/root
        user=$(ls -ld "/proc/$pid" | awk '{ print $3 }')
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
        args=$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null)
        unit=$(awk -F/ '{ for (i = 1; i <= NF; i++) if ($i ~ /\.service$/) { print $i; exit } }' "/proc/$pid/cgroup" 2>/dev/null)

        case $exe in
            *"(deleted)"*)                              flags="$flags DELETED-BIN" ;;
            /tmp/*|/var/tmp/*|/dev/shm/*|/memfd:*|/run/user/*) flags="$flags TMP-BIN" ;;
            /home/*|/root/*)                            flags="$flags HOME-BIN" ;;
        esac
        grep -qE '/docker/|docker-[0-9a-f]{12}|kubepods|libpod-|/lxc' "/proc/$pid/cgroup" 2>/dev/null && flags="$flags CONTAINER"
        [ "$name" = docker-proxy ] && flags="$flags CONTAINER-FWD"

        is_web_name "$name" && web=yes

        # web root: from the web server's own config, else a script path, else a cwd that holds an app
        case $name in
            nginx|openresty)
                path=$(grep -RhEs '(^|[;{[:space:]])root[[:space:]]+[^;[:space:]]+' "$R/etc/nginx" "$R/usr/local/nginx/conf" 2>/dev/null |
                    grep -v '^[[:space:]]*#' | grep -oE 'root[[:space:]]+[^;[:space:]]+' |
                    awk '{ print $2 }' | tr -d '"' | sort -u | tr '\n' ' ') ;;
            apache*|httpd)
                path=$(grep -RhiEs '^[[:space:]]*DocumentRoot[[:space:]]' "$R/etc/apache2" "$R/etc/httpd" "$R/usr/local/apache2/conf" 2>/dev/null |
                    awk '{ print $2 }' | tr -d '"' | sort -u | tr '\n' ' ') ;;
        esac
        if [ -z "$path" ]; then
            script=$(printf '%s\n' "$args" | awk '/\.(py|js|php|rb|jar|war|pl)$/ { print; exit }')
            case $script in
                /*) path=$(dirname "$script") ;;
                ?*) path=$cwd ;;
                *)  [ -n "$cwd" ] && [ "$cwd" != / ] && [ -n "$(app_type "$cwd")" ] && path=$cwd ;;
            esac
        fi
        for d in $path; do
            t=$(app_type "$d")
            if [ -n "$t" ]; then web=yes; roots="$roots$d[$t] "; else roots="$roots$d "; fi
        done

        cfg=$(printf '%s\n' "$args" | awk '/\.(conf|cfg|ini|ya?ml|toml)$/ { printf "%s ", $0 }')

        # master/worker servers: the listener is root, the workers usually are not
        workers=$(ps -eo ppid=,user= 2>/dev/null | awk -v p="$pid" '$1 == p && $2 != "root" { print $2 }' | sort -u | tr '\n' ',' | sed 's/,$//')
        if [ -n "$workers" ] && [ "$user" = root ]; then
            user="root>$workers"
        elif [ "$user" = root ] && [ "$web" = yes ]; then
            flags="$flags ROOT-WEB"
        fi
    else
        flags="$flags NO-OWNER"
    fi

    details=""
    [ -n "$roots" ] && details="$details root=${roots% }"
    [ -n "$cfg" ]   && details="$details cfg=${cfg% }"
    [ -n "$unit" ]  && details="$details unit=$unit"
    [ -n "$exe" ]   && details="$details exe=$exe"
    flags=${flags# }

    if [ "$format" != yaml ]; then
        printf '%-8s %-15s %-7s %-16s %-14s %-22s %s\n' \
            "$port/$proto" "$bind" "$pid" "$name" "$user" "${flags:--}" "${details# }"
    fi

    # record for YAML summary, excluding local-only sockets
    if [ "$bind" != "local" ]; then
        lproto=$(printf '%s' "$proto" | tr 'A-Z' 'a-z')
        ident=$(port_ident "$port" "$lproto")

        if [ "$name" = "-" ] || [ -z "$name" ]; then
            label=${ident:-unknown}
        elif [ -z "$ident" ] || [ "$ident" = "$name" ]; then
            label=$name
        else
            label="$name/$ident"
        fi

        echo "$port $lproto $label" >> "$tmp"
    fi
done

# ---- YAML summary ------------------------------------------------------------

if [ "$format" != table ]; then
    echo
    echo "$host:"
    first_ip=${ips%% *}
    echo "  ip: \"${first_ip:-unknown}\""
    if [ -s "$tmp" ]; then
        echo "  ports:"
        # merge consecutive ports with the same protocol + label into ranges (e.g. 8000-8010/tcp)
        sort -k2,2 -k1,1n "$tmp" |
            awk '{
                if ($2 == p && $3 == l && $1 <= e + 1) { if ($1 > e) e = $1; next }
                if (NR > 1) print s, e, p, l
                s = $1; e = $1; p = $2; l = $3
            } END { if (NR) print s, e, p, l }' |
            sort -k1,1n -k3,3 |
            awk '{ r = ($1 == $2) ? $1 : $1 "-" $2; printf "    \"%s/%s\": %s\n", r, $3, $4 }'
    else
        echo "  ports: {}"
    fi
fi
