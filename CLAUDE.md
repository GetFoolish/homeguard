# MyProxy - Network Traffic Authentication Gateway

**Python Environment**: Use `/Users/vandanchopra/Vandan_Personal_Folder/CODE_STUFF/Projects/myProxy/venv/bin/python`

MY REQUIREMENT:
read the files in the project and understand the project.

Now, here is what i want you to do:
1) Create a file that runs on startup and setup up the following:
    1) ensures that the graphics user interface get 128MB, so that the UI works properly.
    2) ensures that the screensize for VNC is 2048x1152
    3) wifi is turned off, bluetooth is turned off.
    4) There are two ethernet ports set up. and the IP addresses are detected and setup like @scripts/auto-configure-network. The script should automatically figure out it Pi is currently sitting in Inline mode or sideline mode. I want auto-configure-network to do the following: Ethernet port 1 should be .100 and Ethernet port 2 should be .200. 
    5) Also since the file is not only doing network setup but also doing other things, lets call it 'auto-configure-onboot'
    6) also, every time 'auto-configure-onboot' runs, it should clear out the last log file and create a new log file called 'reboot-logs' in the /CODE_STUFF folder and log everything it did to the log file.
    
2) The homeguard project is currently called myproxy. can we change the name of the project everywhere to homeguard.
3) I want homeguard to work only in two modes: 1) transparent mode: where all the traffic is passed through without any intervention. 2) TOTP mode: where all traffic is blocked, and the TOTP authentication page is flashed for when someone tries to access the internet and authenticates them. If they are authenticated, then traffic for that device is let through, and all other devices are still blocked (until they authenticate themselves)
4) Before you start working on fixing all this up, let think about how you want to set up the bridge mode, so that all the traffic from .100 and .200 is going through. The last time we moved the Pi to inline mode, the ssh and vnc and internet all stopped working. Make sure that doesn't happen this time. Make sure you add the final solution to 'auto-configure-onboot'.
5) The way i want you to work on this is first work on step 4 and get bridge mode going, so that we can move the Pi to inline mode and VNC, ssh and internet are all working. Once that is done, then we will do step 1 and 2 and 3.

CLAUDE's WORKFLOW AND PLAN:

Safe Router Mode Configuration - Keep Internet Connected                    │ │
│ │                                                                             │ │
│ │ Current Situation:                                                          │ │
│ │                                                                             │ │
│ │ - Pi has WiFi backup (192.168.4.51) ✅ - KEEP THIS ACTIVE                    │ │
│ │ - Bridge misconfigured with .2.x IPs that can't reach internet ❌            │ │
│ │ - Need router mode (NAT) not bridge mode for inline deployment              │ │
│ │ - Must maintain connectivity throughout process                             │ │
│ │                                                                             │ │
│ │ Safe Configuration Strategy:                                                │ │
│ │                                                                             │ │
│ │ Phase 1: Preserve Connectivity & Fix Bridge (WiFi Backup Active)            │ │
│ │                                                                             │ │
│ │ 1. Keep WiFi connected as backup throughout entire process                  │ │
│ │ 2. Remove problematic .2.x IPs from bridge interface                        │ │
│ │ 3. Configure Pi as Router (not bridge):                                     │ │
│ │   - eth0: WAN interface (gets IP from ISP when inline)                      │ │
│ │   - eth1: LAN interface (serves 192.168.4.x network to WiFi router)         │ │
│ │   - Management: 192.168.4.100 (eth1 side) + WAN IP (eth0 side)              │ │
│ │ 4. Setup NAT/iptables for router mode between eth0 ↔ eth1                   │ │
│ │ 5. Test router functionality in sideline mode                               │ │
│ │                                                                             │ │
│ │ Phase 2: Validate Router Mode (Still Sideline)                              │ │
│ │                                                                             │ │
│ │ 6. Test NAT is working: Traffic flows through Pi router                     │ │
│ │ 7. Verify management access: SSH works via 192.168.4.100                    │ │
│ │ 8. Confirm internet connectivity for test devices                           │ │
│ │ 9. Validate recovery procedures if something breaks                         │ │
│ │                                                                             │ │
│ │ Phase 3: Go Inline (The Big Moment)                                         │ │
│ │                                                                             │ │
│ │ 10. Physical connection change:                                             │ │
│ │   - ISP Router → Pi eth0 (Pi gets ISP IP, probably 192.168.1.x)             │ │
│ │   - Pi eth1 → WiFi Router WAN (Pi provides 192.168.4.1 to WiFi)             │ │
│ │ 11. Pi becomes router between ISP network and WiFi network                  │ │
│ │ 12. Management access:                                                      │ │
│ │   - Primary: ISP-assigned IP (192.168.1.100)                                │ │
│ │   - Secondary: LAN side (192.168.4.100)                                     │ │
│ │                                                                             │ │
│ │ Phase 4: Final Validation & Cleanup                                         │ │
│ │                                                                             │ │
│ │ 13. Test all connectivity: Internet works for all 10 devices                │ │
│ │ 14. Verify management: SSH/VNC accessible from both sides                   │ │
│ │ 15. Disable WiFi backup once everything confirmed working                   │ │
│ │ 16. Document final configuration for auto-configure-onboot                  │ │
│ │                                                                             │ │
│ │ Network Architecture (Final State):                                         │ │
│ │                                                                             │ │
│ │ ISP Router (.1.1) → Pi eth0 (.1.100) [NAT/Router] Pi eth1 (.4.100) → WiFi   │ │
│ │ Router (.4.1)                                                               │ │
│ │                     ↑                                       ↑               │ │
│ │               Management SSH                          Management SSH        │ │
│ │                                                                             │ │
│ │ Safety Features:                                                            │ │
│ │                                                                             │ │
│ │ - WiFi backup: Maintains connectivity throughout process                    │ │
│ │ - Router mode: Handles subnet translation (.1.x ↔ .4.x)                     │ │
│ │ - Dual management: Accessible from both WAN and LAN sides                   │ │
│ │ - NAT handling: Pi manages all traffic translation                          │ │
│ │ - Recovery procedures: Can revert if anything fails                         │ │
│ │                                                                             │ │
│ │ Success Criteria:                                                           │ │
│ │                                                                             │ │
│ │ ✅ Internet never goes down during configuration                             │ │
│ │ ✅ SSH/Claude access maintained via WiFi backup                              │ │
│ │ ✅ Router mode handles 10+ devices seamlessly✅ Management accessible from    │ │
│ │ both network sides                                                          │ │
│ │ ✅ Ready for auto-configure-onboot integration                               │ │
│ │                                                                             │ │
│ │ This approach treats Pi as a proper router (like your home router) rather   │ │
│ │ than a simple bridge, which is what we actually need for inline deployment  │ │
│ │ between different subnets. 




Now we're ready for inline testing. Here's what to do next:

  Step 1: Physical Connection for Testing

  1. Take the ethernet cable that's currently connected to eth1 (USB ethernet)
  2. Connect it to your WiFi router's WAN port (the port that usually connects
  to ISP)
  3. Leave your ISP connection to the WiFi router as-is for now (we're just
  testing)

  Step 2: Activate Pi Gateway Mode

  sudo nmcli connection up HomeguardLAN

  Step 3: Test Gateway Functionality

  After activating HomeguardLAN, test if devices connected to your WiFi can
  still get internet:
  - Try browsing from a phone/laptop connected to WiFi
  - If it works: Pi is successfully acting as gateway! 🎯
  - If it doesn't work: Run sudo nmcli connection down HomeguardLAN to disable

  Step 4: Full Inline Deployment (Only if Step 3 works)

  - Move ISP connection from WiFi router → Pi eth0
  - Pi becomes the main router between ISP and your WiFi network

  Safety Net:

  If anything goes wrong at any step:
  sudo /home/raspberrypi/CODE_STUFF/homeguard/scripts/emergency-restore.sh

  Ready for Step 1? Connect eth1 cable to WiFi router WAN port and let me know
  when done!

