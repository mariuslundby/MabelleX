#!/bin/bash

# Loggfil
LOG_FILE="/var/log/indranavia-wifi-setup.log"

# Funksjon for logging
log() {
   echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Opprett og sikre loggfilen
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Alle output til logg
exec 1>>"$LOG_FILE" 2>&1

log "=== WiFi-konfigurasjon startet ==="

# Sjekk root-rettigheter
if [[ $EUID -ne 0 ]]; then
   log "FEIL: Skriptet må kjøres som root"
   exit 1
fi

# Sjekk om nmcli er tilgjengelig
if ! command -v nmcli &>/dev/null; then
   log "FEIL: nmcli/NetworkManager er ikke installert"
   exit 1
fi

log "nmcli funnet"

# Sjekk om NetworkManager kjører
if ! systemctl is-active --quiet NetworkManager; then
   log "NetworkManager kjører ikke, prøver å starte"
   systemctl start NetworkManager &>/dev/null
   sleep 3
   
   if ! systemctl is-active --quiet NetworkManager; then
      log "FEIL: Kunne ikke starte NetworkManager"
      exit 1
   fi
fi

log "NetworkManager kjører"

# Autodetekter WiFi-grensesnitt
INTERFACE=$(timeout 10s nmcli -t -f DEVICE,TYPE device 2>/dev/null | grep -E ':wifi$' | cut -d':' -f1 | head -n1)

if [[ -z "$INTERFACE" ]]; then
   log "FEIL: Ingen WiFi-grensesnitt funnet"
   exit 1
fi

log "WiFi-grensesnitt funnet: $INTERFACE"

# Aktiver WiFi hvis det er av
timeout 10s nmcli radio wifi on &>/dev/null
sleep 2

# Konfigurasjon
CONN_NAME="IndraNavia-m"
SSID="IndraNavia-m"
PASSWORD="T@keOff2026!"
NEW_PRIORITY=50

OLD_CONN_NAME="Indra-Tilkobling"
OLD_PRIORITY=10

# IDEMPOTENS: Sjekk om tilkobling allerede eksisterer og er korrekt konfigurert
if nmcli connection show "$CONN_NAME" &>/dev/null; then
   log "Tilkobling '$CONN_NAME' eksisterer allerede, sjekker konfigurasjon"
   
   # Sjekk om den er korrekt konfigurert
   CURRENT_PRIORITY=$(timeout 5s nmcli -t -f connection.autoconnect-priority con show "$CONN_NAME" 2>/dev/null | cut -d':' -f2)
   CURRENT_SSID=$(timeout 5s nmcli -t -f 802-11-wireless.ssid con show "$CONN_NAME" 2>/dev/null | cut -d':' -f2)
   CURRENT_HIDDEN=$(timeout 5s nmcli -t -f 802-11-wireless.hidden con show "$CONN_NAME" 2>/dev/null | cut -d':' -f2)
   
   if [[ "$CURRENT_SSID" == "$SSID" && "$CURRENT_PRIORITY" == "$NEW_PRIORITY" && "$CURRENT_HIDDEN" == "yes" ]]; then
      log "IDEMPOTENS: Tilkobling er allerede korrekt konfigurert"
      
      # Sjekk om den er aktiv
      STATUS=$(timeout 5s nmcli -t -f GENERAL.STATE con show "$CONN_NAME" 2>/dev/null)
      if [[ $STATUS == *"activated"* ]]; then
         IP=$(timeout 5s nmcli -t -f IP4.ADDRESS con show "$CONN_NAME" 2>/dev/null | head -n1)
         log "SUKSESS: Tilkobling allerede aktiv med IP $IP"
         exit 0
      else
         log "Tilkobling eksisterer men er ikke aktiv, prøver å aktivere"
         if timeout 30s nmcli connection up "$CONN_NAME" &>/dev/null; then
            sleep 3
            IP=$(timeout 5s nmcli -t -f IP4.ADDRESS con show "$CONN_NAME" 2>/dev/null | head -n1)
            log "SUKSESS: Tilkobling aktivert med IP $IP"
            exit 0
         else
            log "INFO: Tilkobling vil aktiveres automatisk når nettverk er tilgjengelig"
            exit 0
         fi
      fi
   else
      log "Tilkobling eksisterer men er feilkonfigurert, oppdaterer"
      timeout 10s nmcli connection delete "$CONN_NAME" &>/dev/null
   fi
fi

# Scan etter WiFi-nettverk
log "Scanner etter WiFi-nettverk"
timeout 15s nmcli device wifi rescan &>/dev/null
sleep 3

# Sjekk om IndraNavia-m er synlig (kan være skjult)
NETWORK_FOUND=false
if timeout 10s nmcli -t -f SSID device wifi list ifname "$INTERFACE" 2>/dev/null | grep -q "^${SSID}$"; then
   NETWORK_FOUND=true
   log "WiFi-nettverk '$SSID' funnet (synlig)"
else
   log "WiFi-nettverk '$SSID' ikke synlig (kan være skjult nettverk)"
fi

# Sjekk om gammel tilkobling eksisterer
OLD_EXISTS=false
if timeout 5s nmcli connection show "$OLD_CONN_NAME" &>/dev/null; then
   OLD_EXISTS=true
   log "Gammel tilkobling funnet: $OLD_CONN_NAME"
   # Sett lav prioritet på gammel tilkobling som fallback
   timeout 10s nmcli connection modify "$OLD_CONN_NAME" connection.autoconnect-priority $OLD_PRIORITY &>/dev/null
   timeout 10s nmcli connection modify "$OLD_CONN_NAME" connection.autoconnect true &>/dev/null
   log "Gammel tilkobling satt til fallback (prioritet: $OLD_PRIORITY)"
fi

# Opprett ny WiFi-tilkobling
log "Oppretter ny tilkobling til '$SSID' (prioritet: $NEW_PRIORITY)"
if ! timeout 20s nmcli connection add type wifi con-name "$CONN_NAME" ifname "$INTERFACE" ssid "$SSID" \
   connection.autoconnect-priority $NEW_PRIORITY \
   connection.autoconnect-retries 3 &>/dev/null; then
   log "FEIL: Kunne ikke opprette tilkobling (timeout eller feil)"
   exit 1
fi

# Konfigurer sikkerhet (IKKE LOGG PASSORD)
log "Konfigurerer WPA2-PSK sikkerhet"
if ! timeout 10s nmcli connection modify "$CONN_NAME" \
   wifi-sec.key-mgmt wpa-psk \
   wifi-sec.psk "$PASSWORD" &>/dev/null; then
   log "FEIL: Kunne ikke konfigurere sikkerhet"
   exit 1
fi

# Konfigurer for skjult nettverk
timeout 10s nmcli connection modify "$CONN_NAME" \
   wifi.hidden true &>/dev/null

# Optimaliser for rask gjenkobling
timeout 10s nmcli connection modify "$CONN_NAME" \
   connection.autoconnect true \
   connection.auth-retries 3 \
   ipv4.dhcp-timeout 20 \
   ipv6.ip6-privacy 0 &>/dev/null

log "Konfigurasjon fullført (sikkerhet, skjult nettverk og optimalisering)"

# Prøv å aktivere tilkobling (med timeout)
log "Prøver å aktivere ny tilkobling"
if timeout 30s nmcli connection up "$CONN_NAME" &>/dev/null; then
   sleep 3
   
   # Verifiser at tilkoblingen faktisk fungerer
   STATUS=$(timeout 5s nmcli -t -f GENERAL.STATE con show "$CONN_NAME" 2>/dev/null)
   if [[ $STATUS == *"activated"* ]]; then
      IP=$(timeout 5s nmcli -t -f IP4.ADDRESS con show "$CONN_NAME" 2>/dev/null | head -n1)
      log "SUKSESS: Ny tilkobling aktivert med IP $IP"
      
      # Kun nå sletter vi den gamle tilkoblingen
      if [ "$OLD_EXISTS" = true ]; then
         log "Sletter gammel tilkobling: $OLD_CONN_NAME"
         timeout 10s nmcli connection delete "$OLD_CONN_NAME" &>/dev/null
      fi
      
      exit 0
   fi
fi

# Hvis vi kommer hit, er tilkoblingen konfigurert men ikke aktivert
log "ADVARSEL: Kunne ikke aktivere ny tilkobling umiddelbart (timeout eller nettverk utilgjengelig)"

if [ "$OLD_EXISTS" = true ]; then
   log "Beholder gammel tilkobling som fallback"
   log "Ny tilkobling vil automatisk overta når $SSID er tilgjengelig (prioritet: $NEW_PRIORITY)"
else
   log "Ingen fallback tilgjengelig"
   log "Ny tilkobling vil aktiveres automatisk når $SSID er tilgjengelig"
fi

log "=== Konfigurasjon fullført ==="
exit 0