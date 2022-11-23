# SCRIPTED_NMAP: a fastest way to scan vulnerabilities over a network
---------------------------------------------------------------------

this script accelerates nmap vulners script by previously filtering a network via masscan fast scan
then for every occurrency of masscan executes nmap over it with the vulners script
this allow a fastest way to scan large networks for CVE's

## Dependencies

    - massscan  : https://github.com/robertdavidgraham/masscan
    - nmap      : https://nmap.org/


## Usage

(this isn't the last version i need to add CLI Arguments - 23-11-2022)
to use it, you need to modify the capitalized variables inside the script.

### the important ones are:

1. NETWORK
2. MASSCAN_RATE
3. MASSCAN_INITIAL_PORT
4. MASSCAN_FINAL_PORT

then you should put this on a crontab file
you can do it by

```sudo crontab -e```

depending on the network and scan rate this can take a while
when it finally ends, it will give you two outputs

and xml with all ip's with a service detected by masscan
and a txt file that contains vulnerabilities asociated to every service founded

---------------------------------------------------------------------
by ffuenzalid