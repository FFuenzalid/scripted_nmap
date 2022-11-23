# SCRIPTED_NMAP: a fastest way to scan vulnerabilities over a network
---------------------------------------------------------------------

this script accelerates nmap vulners script by previously filtering a network via masscan fast scan
then for every occurrency of masscan executes nmap over it with the vulners script
this allow a fastest way to scan large networks for CVE's

## Dependencies

    - massscan  : https://github.com/robertdavidgraham/masscan
    - nmap      : https://nmap.org/

---------------------------------------------------------------------
by ffuenzalid