# MassVMap: a fastest way to scan vulnerabilities over a network
---------------------------------------------------------------------

this script accelerates nmap vulners script by previously filtering a the network scan via a masscan fast scan
then for every occurrency of masscan executes nmap over it with the vulners script
then it will append all of the data founded to a TXT file (this will change in the future i want a JSON as output)
this allow a fastest way to scan large networks for CVE's

## Dependencies

    - massscan  : https://github.com/robertdavidgraham/masscan
    - nmap      : https://nmap.org/


## Usage

python3 main.py [Network] [-p --ports 1-65535] [-r --rate 5000]

## Protips

a better way to use this script is to add id to the sudo crontab
```sudo crontab -e```

depending on the network and scan rate this can take a while
when it finally ends, it will give you two outputs

and xml with all ip's with a service detected by masscan
and a txt file that contains vulnerabilities asociated to every service founded

## Disclaimer

The use of this tool is at the user's own risk. We will not be liable for any damages or harm that may occur as a result of the use of the tool. 
The user is solely responsible for ensuring that their use of the tool complies with all applicable laws and regulations. 
We will not be responsible for any breach of laws and regulations by the user.

Use it with caution.

---------------------------------------------------------------------
by ffuenzalid