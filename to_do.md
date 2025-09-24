1) when we restart the service, we need to update iptables based on 'authorized' IPs in the database.
2) the splashscreen should show done when the authentication is done. it was done in version-2-updates branch
3) check if traffic only starts work after the 'continue browsing' button is pressed. that shouldn't be the case.
4) we need that feature where we can approve a device from the admin panel, without a TOTP
5) Make sure the service is starting in transparent mode or TOTP mode on boot (the same as the previous setting)