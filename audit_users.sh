#!/usr/bin/env bash
# audit_users.sh
# Lists human users and system users; flags misconfigured system accounts.
# Writes/truncates human_users.txt and system_users.txt.
# Prompts to change password and optionally lock each human user,
# showing group membership before locking.

set -u

HUMAN_FILE="human_users.txt"
SYSTEM_FILE="system_users.txt"
UID_MIN_HUMAN=1000
UID_MAX=65533   # exclude 65534 (nobody) typically

# Determine whether to prefix commands with sudo
if [ "$(id -u)" -eq 0 ]; then
  SUDO_CMD=""
else
  SUDO_CMD="sudo"
fi

echo "Starting user audit..."
echo "Output files: $HUMAN_FILE, $SYSTEM_FILE"

# Helper: get passwd entries via getent (handles LDAP/NIS) or /etc/passwd fallback
get_passwd_entries() {
  if command -v getent >/dev/null 2>&1; then
    getent passwd
  else
    cat /etc/passwd
  fi
}

# 1) Build human users list (UID >= 1000 and < UID_MAX)
echo "Building human users list (UID >= $UID_MIN_HUMAN)..."
: > "$HUMAN_FILE"
get_passwd_entries | awk -F: -v min="$UID_MIN_HUMAN" -v max="$UID_MAX" '
  $3 >= min && $3 <= max { print $1 }
' | sort -u >> "$HUMAN_FILE"

echo "Wrote human users to $HUMAN_FILE"
echo

# 2) Build system users list (UID < 1000)
echo "Building system users list (UID < $UID_MIN_HUMAN)..."
: > "$SYSTEM_FILE"
get_passwd_entries | awk -F: -v min="$UID_MIN_HUMAN" '
  $3 < min { printf "%-20s UID:%-6s HOME:%-25s SHELL:%s\n", $1, $3, $6, $7 }
' | sort >> "$SYSTEM_FILE"

echo "Wrote system users to $SYSTEM_FILE"
echo

# 3) Identify "invalidly configured" system accounts and append to system_users.txt
# Invalid criteria (any of):
#  - shell is a normal login shell (e.g. /bin/bash /bin/sh /bin/zsh /bin/ksh /bin/dash /bin/ash)
#  - home directory is /nonexistent or doesn't exist
#  - password is not locked (we check /etc/shadow if readable)
echo "Scanning system accounts for potentially invalid configurations..."
echo >> "$SYSTEM_FILE"
echo "=== INVALID_SYSTEM_ACCOUNTS (detected on $(date)) ===" >> "$SYSTEM_FILE"

# Build map of shadow password field if readable
declare -A SHADOWPW
if [ -r /etc/shadow ]; then
  while IFS=: read -r su pw rest; do
    SHADOWPW["$su"]="$pw"
  done < /etc/shadow
else
  echo "Warning: cannot read /etc/shadow - some password checks will be skipped." | tee -a "$SYSTEM_FILE"
fi

# Define regex of allowed "nologin" shells and known login shells
nologin_re='nologin|false|/nonexistent'
login_shells_regex='/(bash|sh|zsh|ksh|dash|ash)$'

# Iterate system users and detect issues
while IFS=: read -r username _ uid gid home shell rest; do
  # only system users (UID < MIN)
  if [ "$uid" -ge "$UID_MIN_HUMAN" ]; then
    continue
  fi

  issues=()

  # 3a) login shell is suspicious if it's a normal login shell
  if [[ "$shell" =~ $login_shells_regex ]]; then
    issues+=("has login shell ($shell)")
  fi

  # 3b) home missing or set to /nonexistent
  if [ -z "$home" ] || [ "$home" = "/nonexistent" ] || [ ! -d "$home" ]; then
    issues+=("home missing or /nonexistent ($home)")
  fi

  # 3c) password field in /etc/shadow indicates unlocked/usable password (if we can check)
  if [ -n "${SHADOWPW[$username]:-}" ]; then
    spw="${SHADOWPW[$username]}"
    # locked if starts with '!' or '*' ; treat anything else as possibly set/unlocked
    if [[ "$spw" != '!'* && "$spw" != '*'* && "$spw" != '' ]]; then
      issues+=("password set in /etc/shadow (may be unlockable)")
    fi
  else
    # fallback: try passwd -S (may require sudo)
    if passwd -S "$username" >/dev/null 2>&1; then
      status=$(passwd -S "$username" 2>/dev/null | awk '{print $2}')
      # common statuses: L = locked, NP = no password, P = password set
      if [ "$status" = "P" ] || [ "$status" = "NP" ] || [ "$status" = "L" ]; then
        # treat "P" as possibly set; NP is no password; L locked
        if [ "$status" = "P" ]; then
          issues+=("passwd status: P (password set)")
        fi
      fi
    else
      # unable to determine passwd status; we'll not add issue
      :
    fi
  fi

  if [ "${#issues[@]}" -gt 0 ]; then
    printf "%-20s UID:%-6s HOME:%-25s SHELL:%-20s ISSUES:%s\n" \
      "$username" "$uid" "$home" "$shell" "$(IFS=', '; echo "${issues[*]}")" >> "$SYSTEM_FILE"
  fi

done < <(get_passwd_entries | awk -F: '{print $0}')

echo "Appended invalid system account report to $SYSTEM_FILE"
echo

# 4) Now prompt to change passwords for each human user and optionally lock accounts.
echo "Now iterating human users in $HUMAN_FILE..."
if [ ! -s "$HUMAN_FILE" ]; then
  echo "No human users found in $HUMAN_FILE. Exiting."
  exit 0
fi

while IFS= read -r user || [ -n "$user" ]; do
  # skip empty lines
  if [ -z "$user" ]; then
    continue
  fi

  # verify user exists
  if ! id "$user" >/dev/null 2>&1; then
    echo "User '$user' not found on system, skipping."
    continue
  fi

  echo
  echo "User: $user"
  # show basic info
  getent passwd "$user" | awk -F: '{printf "UID:%s HOME:%s SHELL:%s\n", $3,$6,$7}'

  # Ask to change password
  while true; do
    read -r -p "Change password for $user? [y/N]: " changepw
    changepw=${changepw:-N}
    case "$changepw" in
      [Yy]* )
        echo "Changing password for $user..."
        # call passwd (will prompt for new password)
        if ! $SUDO_CMD passwd "$user"; then
          echo "passwd failed for $user (you may need root/sudo)."
        fi
        break
        ;;
      [Nn]*|"" )
        echo "Skipping password change for $user."
        break
        ;;
      * )
        echo "Please answer y or n."
        ;;
    esac
  done

  # Show groups before asking to lock
  echo "Groups for $user:"
  if id -nG "$user" >/dev/null 2>&1; then
    id -nG "$user" | tr ' ' '\n' | sed 's/^/  - /'
  else
    groups "$user" 2>/dev/null || echo "  (could not determine groups)"
  fi

  # Ask to lock account
  while true; do
    read -r -p "Lock account $user? [y/N]: " lockans
    lockans=${lockans:-N}
    case "$lockans" in
      [Yy]* )
        echo "Locking account $user..."
        if ! $SUDO_CMD passwd -l "$user"; then
          echo "Failed to lock $user (check permissions)."
        else
          echo "$user locked."
        fi
        break
        ;;
      [Nn]*|"" )
        echo "Leaving $user unlocked."
        break
        ;;
      * )
        echo "Please answer y or n."
        ;;
    esac
  done

done < "$HUMAN_FILE"

echo
echo "Audit complete."
echo "Human users written to: $HUMAN_FILE"
echo "System users written to: $SYSTEM_FILE"
echo "Review $SYSTEM_FILE carefully for the 'INVALID_SYSTEM_ACCOUNTS' section."

exit 0