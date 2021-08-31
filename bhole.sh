#!/usr/bin/env bash
# shellcheck disable=SC1090

bholedebug="no"

# thanks https://serverfault.com/a/103569
if [ ${bholedebug} = 'no' ]; then
  exec 3>&1 4>&2
  trap 'exec 2>&4 1>&3' 0 1 2 3
  exec 1>log.out 2>&1
fi

# Determine if terminal is capable of showing colours
if [[ -t 1 ]] && [[ $(tput colors) -ge 8 ]]; then
  # Bold and underline may not show up on all clients
  # If something MUST be emphasised, use both
  COL_BOLD='[1m'
  COL_ULINE='[4m'

  COL_NC='[0m'
  COL_GRAY='[90m'
  COL_RED='[91m'
  COL_GREEN='[32m'
  COL_YELLOW='[33m'
  COL_BLUE='[94m'
  COL_PURPLE='[95m'
  COL_CYAN='[96m'
else
  # Provide empty variables for `set -u`
  COL_BOLD=""
  COL_ULINE=""

  COL_NC=""
  COL_GRAY=""
  COL_RED=""
  COL_GREEN=""
  COL_YELLOW=""
  COL_BLUE=""
  COL_PURPLE=""
  COL_CYAN=""
fi

TICK="[${COL_GREEN}✓${COL_NC}]"
CROSS="[${COL_RED}✗${COL_NC}]"
INFO="[i]"
QST="[?]"
DONE="${COL_GREEN} done!${COL_NC}"
OVER="\\r[K"

IPV4_ADDRESS="0.0.0.0"
IPV6_ADDRESS="::/0"
IPV4_ADDRESS="${IPV4_ADDRESS%/*}"
IPV6_ADDRESS="${IPV6_ADDRESS%/*}"

basename="pihole"

if [ ${bholedebug} = 'yes' ]; then
  piholeDir="$(pwd)"
else
  piholeDir="/usr/local/etc/bhole"
fi

adListFile="${piholeDir}/tick_list.txt"
adListDefault="${piholeDir}/adlists.default"

whitelistFile="${piholeDir}/whitelist.txt"
blacklistFile="${piholeDir}/blacklist.txt"

adList="${piholeDir}/gravity.list"
blackList="${piholeDir}/black.list"
localList="${piholeDir}/local.list"
VPNList="/etc/openvpn/ipp.txt"

domainsExtension="domains"
matterAndLight="${basename}.0.matterandlight.txt"
parsedMatter="${basename}.1.parsedmatter.txt"
whitelistMatter="${basename}.2.whitelistmatter.txt"
accretionDisc="${basename}.3.accretionDisc.txt"
preEventHorizon="list.preEventHorizon"

listurl="https://v.firebog.net/hosts/lists.php?type=tick"
whitelisturl="https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt"

# Try to update the curated white list from github
gravity_fetch_white() {
  if [[ -z ${whitelistFile} ]]; then
    # we have a list already, fetch a new one
    newwhitelist=$(mktemp /tmp/bhole.XXXX)
    curl -o ${newwhitelist} ${listurl}
    if [[ -z ${newwhitelist} ]]; then
      rm ${whitelistFile}
      mv ${newwhitelist} ${whitelistFile}
    fi
  else
    # Must not have a list, and we need one
    curl -o ${whitelistFile} ${whitelisturl}
  fi
}

# Try to update the tick_list of "safe" domains to block
gravity_ticklist() {
  if [[ -z ${adListFile} ]]; then
    # we have a list already, fetch a new one
    newticklist=$(mktemp /tmp/bhole.XXXX)
    curl -o ${newticklist} ${listurl}
    if [[ -z ${newticklist} ]]; then
      rm ${adListFile}
      mv ${newticklist} ${adListFile}
    fi
  else
    # Must not have a list, and we need one
    curl -o ${adListFile} ${listurl}
  fi
}

# Retrieve blocklist URLs and parse domains from adlists.list
gravity_GetBlocklistUrls() {
  echo -e "  ${INFO} ${COL_BOLD}Neutrino emissions detected${COL_NC}..."

  # Retrieve source URLs from $adListFile
  # Logic: Remove comments and empty lines
  mapfile -t sources <<< "$(grep -v -E "^(#|$)" "${adListFile}")"

  # Parse source domains from $sources
  mapfile -t sourceDomains <<< "$(
    # Logic: Split by folder/port
    gawk -F '[/:]' '{
      # Remove URL protocol & optional username:password@
      gsub(/(.*:\/\/|.*:.*@)/, "", $0)
      if(length($1)>0){print $1}
      else {print "local"}
    }' <<< "$(printf '%s\n' "${sources[@]}")" 2> /dev/null
  )"

  local str="Pulling blocklist source list into range"

  if [[ -n "${sources[*]}" ]] && [[ -n "${sourceDomains[*]}" ]]; then
    echo -e "${OVER}  ${TICK} ${str}"
  else
    echo -e "${OVER}  ${CROSS} ${str}"
    echo -e "  ${INFO} No source list found, or it is empty"
    echo ""
    haveSourceUrls=false
  fi
}

# Define options for when retrieving blocklists
gravity_SetDownloadOptions() {
  local url domain agent cmd_ext str

  echo ""

  # Loop through $sources and download each one
  for ((i = 0; i < "${#sources[@]}"; i++)); do
    url="${sources[$i]}"
    domain="${sourceDomains[$i]}"

    # Save the file as list.#.domain
    saveLocation="${piholeDir}/list.${i}.${domain}.${domainsExtension}"
    activeDomains[$i]="${saveLocation}"

    # Default user-agent (for Cloudflare's Browser Integrity Check: https://support.cloudflare.com/hc/en-us/articles/200170086-What-does-the-Browser-Integrity-Check-do-)
    agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36"

    # Provide special commands for blocklists which may need them
    case "${domain}" in
      "pgl.yoyo.org") cmd_ext="-d mimetype=plaintext -d hostformat=hosts";;
      *) cmd_ext="";;
    esac

    echo -e "  ${INFO} Target: ${domain} (${url##*/})"
    gravity_DownloadBlocklistFromUrl "${url}" "${cmd_ext}" "${agent}"
    echo ""
  done
  gravity_Blackbody=true
}

# Download specified URL and perform checks on HTTP status and file content
gravity_DownloadBlocklistFromUrl() {
  local url="${1}" cmd_ext="${2}" agent="${3}" heisenbergCompensator="" patternBuffer str httpCode success=""

  # Create temp file to store content on disk instead of RAM
  patternBuffer=$(mktemp)

  # Determine if $saveLocation has read permission
  if [[ -r "${saveLocation}" && $url != "file"* ]]; then
    # Have curl determine if a remote file has been modified since last retrieval
    # Uses "Last-Modified" header, which certain web servers do not provide (e.g: raw github urls)
    # Note: Don't do this for local files, always download them
    heisenbergCompensator="-z ${saveLocation}"
  fi

  str="Status:"
  echo -ne "  ${INFO} ${str} Pending..."
  # shellcheck disable=SC2086
  httpCode=$(curl -m 7 -s -L ${cmd_ext} ${heisenbergCompensator} -w "%{http_code}" -A "${agent}" "${url}" -o "${patternBuffer}" 2> /dev/null)

  case $url in
    # Did we "download" a local file?
    "file"*)
        if [[ -s "${patternBuffer}" ]]; then
          echo -e "${OVER}  ${TICK} ${str} Retrieval successful"; success=true
        else
          echo -e "${OVER}  ${CROSS} ${str} Not found / empty list"
        fi;;
    # Did we "download" a remote file?
    *)
      # Determine "Status:" output based on HTTP response
      case "${httpCode}" in
        "200") echo -e "${OVER}  ${TICK} ${str} Retrieval successful"; success=true;;
        "304") echo -e "${OVER}  ${TICK} ${str} No changes detected"; success=true;;
        "000") echo -e "${OVER}  ${CROSS} ${str} Connection Refused";;
        "403") echo -e "${OVER}  ${CROSS} ${str} Forbidden";;
        "404") echo -e "${OVER}  ${CROSS} ${str} Not found";;
        "408") echo -e "${OVER}  ${CROSS} ${str} Time-out";;
        "451") echo -e "${OVER}  ${CROSS} ${str} Unavailable For Legal Reasons";;
        "500") echo -e "${OVER}  ${CROSS} ${str} Internal Server Error";;
        "504") echo -e "${OVER}  ${CROSS} ${str} Connection Timed Out (Gateway)";;
        "521") echo -e "${OVER}  ${CROSS} ${str} Web Server Is Down (Cloudflare)";;
        "522") echo -e "${OVER}  ${CROSS} ${str} Connection Timed Out (Cloudflare)";;
        *    ) echo -e "${OVER}  ${CROSS} ${str} ${url} (${httpCode})";;
      esac;;
  esac

  # Determine if the blocklist was downloaded and saved correctly
  if [[ "${success}" == true ]]; then
    if [[ "${httpCode}" == "304" ]]; then
      : # Do not attempt to re-parse file
    # Check if $patternbuffer is a non-zero length file
    elif [[ -s "${patternBuffer}" ]]; then
      # Determine if blocklist is non-standard and parse as appropriate
      gravity_ParseFileIntoDomains "${patternBuffer}" "${saveLocation}"
    else
      # Fall back to previously cached list if $patternBuffer is empty
      echo -e "  ${INFO} Received empty file: ${COL_LIGHT_GREEN}using previously cached list${COL_NC}"
    fi
  else
    # Determine if cached list has read permission
    if [[ -r "${saveLocation}" ]]; then
      echo -e "  ${CROSS} List download failed: ${COL_LIGHT_GREEN}using previously cached list${COL_NC}"
    else
      echo -e "  ${CROSS} List download failed: ${COL_LIGHT_RED}no cached list available${COL_NC}"
    fi
  fi
}

# Parse source files into domains format
gravity_ParseFileIntoDomains() {
  local source="${1}" destination="${2}" firstLine abpFilter

  # Determine if we are parsing a consolidated list
  if [[ "${source}" == "${piholeDir}/${matterAndLight}" ]]; then
    # Remove comments and print only the domain name
    # Most of the lists downloaded are already in hosts file format but the spacing/formating is not contigious
    # This helps with that and makes it easier to read
    # It also helps with debugging so each stage of the script can be researched more in depth
    # gAwk -F splits on given IFS, we grab the right hand side (chops trailing #coments and /'s to grab the domain only.
    # Last gawk command takes non-commented lines and if they have 2 fields, take the right field (the domain) and leave
    # the left (IP address), otherwise grab the single field.

    < ${source} gawk -F '#' '{print $1}' | \
    gawk -F '/' '{print $1}' | \
    gawk '($1 !~ /^#/) { if (NF>1) {print $2} else {print $1}}' | \
    gsed -nr -e 's/\.{2,}/./g' -e '/\./p' >  ${destination}
    return 0
  fi

  # Individual file parsing: Keep comments, while parsing domains from each line
  # We keep comments to respect the list maintainer's licensing
  read -r firstLine < "${source}"

  # Determine how to parse individual source file formats
  if [[ "${firstLine,,}" =~ (adblock|ublock|^!) ]]; then
    # Compare $firstLine against lower case words found in Adblock lists
    echo -ne "  ${INFO} Format: Adblock"

    # Define symbols used as comments: [!
    # "||.*^" includes the "Example 2" domains we can extract
    # https://adblockplus.org/filter-cheatsheet
    abpFilter="/^(\\[|!)|^(\\|\\|.*\\^)/"

    # Parse Adblock lists by extracting "Example 2" domains
    # Logic: Ignore lines which do not include comments or domain name anchor
    gawk ''"${abpFilter}"' {
      # Remove valid adblock type options
      gsub(/\$?~?(important|third-party|popup|subdocument|websocket),?/, "", $0)
      # Remove starting domain name anchor "||" and ending seperator "^"
      gsub(/^(\|\|)|(\^)/, "", $0)
      # Remove invalid characters (*/,=$)
      if($0 ~ /[*\/,=\$]/) { $0="" }
      # Remove lines which are only IPv4 addresses
      if($0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) { $0="" }
      if($0) { print $0 }
    }' "${source}" > "${destination}"

    # Determine if there are Adblock exception rules
    # https://adblockplus.org/filters
    if grep -q "^@@||" "${source}" &> /dev/null; then
      # Parse Adblock lists by extracting exception rules
      # Logic: Ignore lines which do not include exception format "@@||example.com^"
      gawk -F "[|^]" '/^@@\|\|.*\^/ {
        # Remove valid adblock type options
        gsub(/\$?~?(third-party)/, "", $0)
        # Remove invalid characters (*/,=$)
        if($0 ~ /[*\/,=\$]/) { $0="" }
        if($3) { print $3 }
      }' "${source}" > "${destination}.exceptionsFile.tmp"

      # Remove exceptions
      comm -23 "${destination}" <(sort "${destination}.exceptionsFile.tmp") > "${source}"
      mv "${source}" "${destination}"
    fi

    echo -e "${OVER}  ${TICK} Format: Adblock"
  elif grep -q "^address=/" "${source}" &> /dev/null; then
    # Parse Dnsmasq format lists
    echo -e "  ${CROSS} Format: Dnsmasq (list type not supported)"
  elif grep -q -E "^https?://" "${source}" &> /dev/null; then
    # Parse URL list if source file contains "http://" or "https://"
    # Scanning for "^IPv4$" is too slow with large (1M) lists on low-end hardware
    echo -ne "  ${INFO} Format: URL"

    gawk '
      # Remove URL scheme, optional "username:password@", and ":?/;"
      # The scheme must be matched carefully to avoid blocking the wrong URL
      # in cases like:
      #   http://www.evil.com?http://www.good.com
      # See RFC 3986 section 3.1 for details.
      /[:?\/;]/ { gsub(/(^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(.*:.*@)?|[:?\/;].*)/, "", $0) }
      # Skip lines which are only IPv4 addresses
      /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
      # Print if nonempty
      length { print }
    ' "${source}" 2> /dev/null > "${destination}"

    echo -e "${OVER}  ${TICK} Format: URL"
  else
    # Default: Keep hosts/domains file in same format as it was downloaded
    output=$( { mv "${source}" "${destination}"; } 2>&1 )

    if [[ ! -e "${destination}" ]]; then
      echo -e "\\n  ${CROSS} Unable to move tmp file to ${piholeDir}
    ${output}"
      gravity_Cleanup "error"
    fi
  fi
}

# Create (unfiltered) "Matter and Light" consolidated list
gravity_ConsolidateDownloadedBlocklists() {
  local str lastLine

  str="Consolidating blocklists"
  if [[ "${haveSourceUrls}" == true ]]; then
    echo -ne "  ${INFO} ${str}..."
  fi

  # Empty $matterAndLight if it already exists, otherwise, create it
  : > "${piholeDir}/${matterAndLight}"

  # Loop through each *.domains file
  for i in "${activeDomains[@]}"; do
    # Determine if file has read permissions, as download might have failed
    if [[ -r "${i}" ]]; then
      # Remove windows CRs from file, convert list to lower case, and append into $matterAndLight
      gtr -d '\r' < "${i}" | gtr '[:upper:]' '[:lower:]' >> "${piholeDir}/${matterAndLight}"

      # Ensure that the first line of a new list is on a new line
      lastLine=$(tail -1 "${piholeDir}/${matterAndLight}")
      if [[ "${#lastLine}" -gt 0 ]]; then
        echo "" >> "${piholeDir}/${matterAndLight}"
      fi
    fi
  done
  if [[ "${haveSourceUrls}" == true ]]; then
    echo -e "${OVER}  ${TICK} ${str}"
  fi
}

# Parse consolidated list into (filtered, unique) domains-only format
gravity_SortAndFilterConsolidatedList() {
  local str num

  str="Extracting domains from blocklists"
  if [[ "${haveSourceUrls}" == true ]]; then
    echo -ne "  ${INFO} ${str}..."
  fi

  # Parse into hosts file
  gravity_ParseFileIntoDomains "${piholeDir}/${matterAndLight}" "${piholeDir}/${parsedMatter}"

  # Format $parsedMatter line total as currency
  num=$(printf "%'.0f" "$(wc -l < "${piholeDir}/${parsedMatter}")")
  if [[ "${haveSourceUrls}" == true ]]; then
    echo -e "${OVER}  ${TICK} ${str}"
  fi
  echo -e "  ${INFO} Number of domains being pulled in by gravity: ${COL_BLUE}${num}${COL_NC}"

  str="Removing duplicate domains"
  if [[ "${haveSourceUrls}" == true ]]; then
    echo -ne "  ${INFO} ${str}..."
  fi

  sort -u "${piholeDir}/${parsedMatter}" > "${piholeDir}/${preEventHorizon}"

  if [[ "${haveSourceUrls}" == true ]]; then
    echo -e "${OVER}  ${TICK} ${str}"
    # Format $preEventHorizon line total as currency
    num=$(printf "%'.0f" "$(wc -l < "${piholeDir}/${preEventHorizon}")")
    echo -e "  ${INFO} Number of unique domains trapped in the Event Horizon: ${COL_BLUE}${num}${COL_NC}"
  fi
}

# Whitelist user-defined domains
gravity_Whitelist() {
  local num str

  if [[ ! -f "${whitelistFile}" ]]; then
    echo -e "  ${INFO} Nothing to whitelist!"
    return 0
  fi

  num=$(wc -l < "${whitelistFile}")
  str="Number of whitelisted domains: ${num}"
  echo -ne "  ${INFO} ${str}..."

  # Print everything from preEventHorizon into whitelistMatter EXCEPT domains in $whitelistFile
  comm -23 "${piholeDir}/${preEventHorizon}" <(sort "${whitelistFile}") > "${piholeDir}/${whitelistMatter}"

  echo -e "${OVER}  ${INFO} ${str}"
}

# Output count of blacklisted domains and regex filters
gravity_ShowBlockCount() {
  local num

  if [[ -f "${blacklistFile}" ]]; then
    num=$(printf "%'.0f" "$(wc -l < "${blacklistFile}")")
    echo -e "  ${INFO} Number of blacklisted domains: ${num}"
  fi

  if [[ -f "${regexFile}" ]]; then
    num=$(grep -c "^(?!#)" "${regexFile}")
    echo -e "  ${INFO} Number of regex filters: ${num}"
  fi
}

# Parse list of domains into hosts format
gravity_ParseDomainsIntoHosts() {
  gawk -v ipv4="$IPV4_ADDRESS" -v ipv6="$IPV6_ADDRESS" '{
    # Remove windows CR line endings
    sub(/\r$/, "")
    # Parse each line as "ipaddr domain"
    if(ipv6 && ipv4) {
      print ipv4" "$0"\n"ipv6" "$0
    } else if(!ipv6) {
      print ipv4" "$0
    } else {
      print ipv6" "$0
    }
  }' >> "${2}" < "${1}"
}

# Create "localhost" entries into hosts format
gravity_ParseLocalDomains() {
  local hostname

  if [[ -s "/etc/hostname" ]]; then
    hostname=$(< "/etc/hostname")
  elif command -v hostname &> /dev/null; then
    hostname=$(hostname -f)
  else
    echo -e "  ${CROSS} Unable to determine fully qualified domain name of host"
    return 0
  fi

  echo -e "${hostname}\\npi.hole" > "${localList}.tmp"

  # Empty $localList if it already exists, otherwise, create it
  : > "${localList}"

  gravity_ParseDomainsIntoHosts "${localList}.tmp" "${localList}"

  # Add additional LAN hosts provided by OpenVPN (if available)
  if [[ -f "${VPNList}" ]]; then
    awk -F, '{printf $2"\t"$1".vpn\n"}' "${VPNList}" >> "${localList}"
  fi
}

# Create primary blacklist entries
gravity_ParseBlacklistDomains() {
  local output status

  # Empty $accretionDisc if it already exists, otherwise, create it
  : > "${piholeDir}/${accretionDisc}"

  if [[ -f "${piholeDir}/${whitelistMatter}" ]]; then
    mv "${piholeDir}/${whitelistMatter}" "${piholeDir}/${accretionDisc}"
  else
    # There was no whitelist file, so use preEventHorizon instead of whitelistMatter.
    mv "${piholeDir}/${preEventHorizon}" "${piholeDir}/${accretionDisc}"
  fi

  # Move the file over as /etc/pihole/gravity.list so dnsmasq can use it
  output=$( { mv "${piholeDir}/${accretionDisc}" "${adList}"; } 2>&1 )
  status="$?"

  if [[ "${status}" -ne 0 ]]; then
    echo -e "\\n  ${CROSS} Unable to move ${accretionDisc} from ${piholeDir}\\n  ${output}"
    gravity_Cleanup "error"
  fi
}

# Create user-added blacklist entries
gravity_ParseUserDomains() {
  if [[ ! -f "${blacklistFile}" ]]; then
    return 0
  fi
  # Copy the file over as /etc/pihole/black.list so dnsmasq can use it
  cp "${blacklistFile}" "${blackList}" 2> /dev/null || \
    echo -e "\\n  ${CROSS} Unable to move ${blacklistFile##*/} to ${piholeDir}"
}

# Trap Ctrl-C
gravity_Trap() {
  trap '{ echo -e "\\n\\n  ${INFO} ${COL_LIGHT_RED}User-abort detected${COL_NC}"; gravity_Cleanup "error"; }' INT
}

# Clean up after Gravity upon exit or cancellation
gravity_Cleanup() {
  local error="${1:-}"

  str="Cleaning up stray matter"
  echo -ne "  ${INFO} ${str}..."

  # Delete tmp content generated by Gravity
  rm ${piholeDir}/pihole.*.txt 2> /dev/null
  rm ${piholeDir}/*.tmp 2> /dev/null
  rm /tmp/*.phgpb 2> /dev/null

  # Ensure this function only runs when gravity_SetDownloadOptions() has completed
  if [[ "${gravity_Blackbody:-}" == true ]]; then
    # Remove any unused .domains files
    for file in ${piholeDir}/*.${domainsExtension}; do
      # If list is not in active array, then remove it
      if [[ ! "${activeDomains[*]}" == *"${file}"* ]]; then
        rm -f "${file}" 2> /dev/null || \
          echo -e "  ${CROSS} Failed to remove ${file##*/}"
      fi
    done
  fi

  echo -e "${OVER}  ${TICK} ${str}"


  # Print Pi-hole status if an error occured
  if [[ -n "${error}" ]]; then
    "${PIHOLE_COMMAND}" status
    exit 1
  fi
}

# Convert the contets into a format unbound can read
gravity_unbound() {
  # Parse into a format for Unbound
  echo -e "  ${INFO} ${COL_BOLD}Unbinding Matter and Light${COL_NC}..."

  # Makre sure we don't have crufty old files
  if [[ -s ${piholeDir}/ads4.conf ]]; then
    rm ${piholeDir}/ads4.conf
  fi

  if [[ -s ${piholeDir}/ads6.conf ]]; then
    rm ${piholeDir}/ads6.conf
  fi

  # Remove bad entries
  sed -i '' "/if-a-large-hosts-file-contains-this-entry-then-it-uses-dandelion-sprouts-anti-malware-list-as-one-of-its-source-lists.data/d" ${adList}
  sed -i '' "/^[[:space:]]*$/d" ${adList}

  # Turn the correct file into unbound config
  awk '{print "local-zone: \""$1"\" redirect\nlocal-data: \""$1" A 0.0.0.0\""}' ${adList} > ${piholeDir}/ads4.conf

  echo -e "  ${OVER}  ${TICK} Unbound configs are ready!${COL_NC}"
  echo -e "  ${INFO} ${COL_BOLD}Please make sure you have the right include: ads4/6.conf lines in unbound.conf${COL_NC}"
}

# Trap Ctrl-C
gravity_Trap

gravity_fetch_white

gravity_ticklist

# Let's just do it.
gravity_GetBlocklistUrls

gravity_SetDownloadOptions

gravity_ConsolidateDownloadedBlocklists

gravity_SortAndFilterConsolidatedList

# Perform when downloading blocklists, or modifying the whitelist

gravity_Whitelist

gravity_ShowBlockCount

str="Parsing domains into hosts format"
echo -ne "  ${INFO} ${str}..."

gravity_ParseUserDomains

gravity_ParseLocalDomains

gravity_ParseBlacklistDomains

echo -e "${OVER}  ${TICK} ${str}"

gravity_Cleanup

echo ""

gravity_unbound

if [ ${bholedebug} = 'no' ]; then
  # Not debug, restart unbound
  service unbound restart
else
  unbound-checkconf unbound.conf
fi

