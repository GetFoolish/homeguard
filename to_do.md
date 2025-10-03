(DONE IN VERSION 3) 1) when we restart the service, we need to update iptables based on 'authorized' IPs in the database. There could be IPs that have put in their TOTP and have time left on the meter. I don't want them to suffer and have to put the TOTP again just because we srestarted the service.
(DONE IN VERSION 3) 2) the splashscreen implementation in 'version-2-updates' branch was done very beautifully with the console catch working perfectly across mac, android, windows and linux. can we see what we were doing there and learn from it and implement something like that in this branch.
(DONE IN VERSION 3) 3) check if traffic only starts work after the 'continue browsing' button is pressed. that shouldn't be the case.
(DONE IN VERSION 3) 5) Make sure the service is starting in transparent mode or TOTP mode on boot (the same as the previous setting)
---------------------------------------------------------------------------------------------------
4) App.py has become too big again. 
1) TOTPs are suddenly not working. and not refreshing on the admin panel automatically every 30 seconds.
2) we need that feature where we can approve a device from the admin panel, without a TOTP.
3) We need to see the logs on the Gateway section at the bottom in reverse order. also change log file from myproxy.log to homeguard.log
5) Remove HOMEGUARD_FILTER from this project. we're using HOMEGUARD_ACCEPT and HOMEGUARD_BLOCK now.
6) IOT Devices management
