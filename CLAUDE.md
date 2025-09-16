# HomeguardGuard - Network Traffic Authentication Gateway

**Python Environment**: Use `/Users/vandanchopra/Vandan_Personal_Folder/CODE_STUFF/Projects/myProxy/venv/bin/python`

1) Make the system work like this:

  1) Transparent Mode:

  FORWARD Chain:
  1. ACCEPT tcp dport 22,5900,8081
  2. ACCEPT tcp sport 22,5900,8081 ctstate RELATED,ESTABLISHED
  4. ACCEPT eth1→eth0 (outbound traffic)
  5. ACCEPT eth0→eth1 ctstate RELATED,ESTABLISHED (return traffic)

  HOMEGUARD_FILTER Chain:
  (Empty - not used)

  Result: No blocking + SSH/VNC/Web Admin always work

2) TOTP Full after restart:

  FORWARD Chain:

  1. ACCEPT tcp dport 22,5900,8081
  2. ACCEPT tcp sport 22,5900,8081 ctstate RELATED,ESTABLISHED
  3. HOMEGUARD_FILTER (for client traffic policing only)

  HOMEGUARD_FILTER Chain:
	(Empty)

3) After User Enters Valid TOTP:

  FORWARD Chain: (stays the same)
  1. ACCEPT tcp dport 22,5900,8081
  2. ACCEPT tcp sport 22,5900,8081 ctstate RELATED,ESTABLISHED
  4. HOMEGUARD_FILTER

  HOMEGUARD_FILTER Chain: (gets new rule added)
 1. ACCEPT -s 192.168.2.71 (authenticated device gets added)

  Result: That specific device (192.168.2.71) gets internet access, all other devices still blocked

  ---
  Multiple Users Authenticate:

  HOMEGUARD_FILTER Chain:
 1. ACCEPT -s 192.168.2.71 (first authenticated device)
  2. ACCEPT -s 192.168.2.85 (second authenticated device)
  3. ACCEPT -s 192.168.2.92 (third authenticated device)

  Result: Only authenticated devices get internet, unauthenticated devices remain blocked

 When Timer Expires or Access Revoked:

  The specific device rule gets REMOVED from HOMEGUARD_FILTER:
  2. ACCEPT -s 192.168.2.85 (still valid)
  3. ACCEPT -s 192.168.2.92 (still valid)
  (192.168.2.71 rule REMOVED)

  Result: Device 192.168.2.71 loses internet immediately, others keep access

  HOMEGUARD_FILTER rules dynamically change as users authenticate and sessions expire, but the FORWARD management rules stay constant.

I want the system have 2 modes: testing, and live. 
In testing mode it only creates the desired iptables setup in a json.
In live mode, it actually makes changes to the IP tables as required, and checks the desired-ip-tables setup and the actual IP tables deployed every 5 minutes and makes changes as desired.

2) How is it keeping track of running TOTP timers? And how are rule changes triggered when access is revoked or the timer runs out?

3) Can you check how and where we are keeping a track of authenticated / unauthenticated IPs in the database.
5) the TOTP frontend /authenticate page is not required. Once the TOTP has been accepted, it should go back to / where the timer is shown.
6) The admin panel page where the current mode is shown, and the buttons for mode change exist, the system should automatically switch and activate when the mode is changed, rather than it requiring a restart manually by the user. Also, lets have the script output printed to the admin page when the mode is switched.
7) Change the name of the project from homeguard to Homeguard. I don’t want to see homeguard anywhere, it should be homeguard_filters, homeguard in the code, homeguard in the folder and filenames.
8) Make sure the project starts on reboot automatically.


9) When a user is not authenticated, and they go to a url, it should automatically redirect to the authentication url.
10) Setup captive portal redirect:  Automatic Detection: When devices connect to WiFi, they automatically check internet connectivity by trying to reach:
  - http://detectportal.firefox.com/ (Firefox)
  - http://www.msftconnecttest.com/ (Windows)
  - http://connectivitycheck.gstatic.com/ (Android)
  - http://captive.apple.com/ (Apple devices)

  What Happens:

  1. Device connects to WiFi
  2. Device tries connectivity check → Gets blocked by our firewall
  3. Device detects captive portal → Chrome/browser opens automatically
  4. Browser shows: "Sign in to network" notification
  5. User clicks → Redirected to our auth page

  Implementation:

  Setup captive portal redirect:
  # Block connectivity checks → Force captive portal detection
  iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8081

  Result:
  - ✅ Netflix app fails → Triggers captive portal detection
  - ✅ Chrome opens automatically with "Sign in to network"
  - ✅ User gets redirected to http://homeguard.local or our auth page
  - ✅ Works on all devices (phones, laptops, tablets)

  User Experience:

  1. User opens Netflix app → "No internet"
  2. Phone automatically opens Chrome → "Sign in to network"
  3. User taps "Sign in" → Gets our TOTP auth page
  4. User enters TOTP → Gets internet access

  This is exactly how hotel/airport WiFi works! Very familiar user experience.

