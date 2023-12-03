# Logfile Ethical hacking Python

Starting of with exploring the libraries that were given to us as an interesting starting point, aswell as exploring the given demo scripts to see how certain libraries work.

Furthermore I started to develop a website with python as base language, at first i tried doing this with streamlit but after a couple of problems I switched over to using flask library and just a template html. In this website i'm basically trying to give the user a gui or a frontend for easy usage, what actually happens is all done behind the screens.

For example, the user wants to find the ip address, location and other information about a certain website, then he can do so by simply entering the website like 'google.com' in the input field and press the button next to it. The results will be displayed both in rich in the terminal aswell as in the webpage.

## Deadline 1

### Scripts and libraries

Changed Demo script 1 and 2 to a more OOP style so i could easily intergrate them in my project.

Added DNS Sec validation script and a WhoIs script for domain lookup details. Found suspicion to wheter the results were correct or not for headers but after further investigation it does seem so.

Played around with the rich library in combination with the flash usage so i get a nice clean output in both terminal as in the html, however there's no terminal input option yet so user still has to use html for usage.

### Worked hours

Around 6 to 7 Hours up to now.  Not fully finished (in depth wise) but spend some time to styling.

## Deadline 2

### Scripts

Added NetworkScanner as scappy file, with OOP style. Integrated it into main but not finished it properly. questioning if HTTP traffic scan actually works according, struggling currently with the OS detection and http traffic scan.

Will have to make time for checking and reviewing all previous code and styling.

### Worked hours

around 3 to 4 hours, for just the scappy file (NetworkScannerScapy.py). Should've done better, will have to make time before next deadline for cleaning up project part1 and 2 with adding next upcoming part 3.

## Deadline 3

### Scripts

Continued the NetworkScannerScapy with a seperate HostDiscovery file which took a while, eventually got help from a colleague. Cleaned up code from previous functions.

Played around with Man In the Middle script but i still want to throw it's current working method around just for personal preference.

Added a credential sniffer but haven't been able to validate it's functionality, just throws me an endless loop so far i can see. Going to be looking to refactor or even rewrite the previous code so i can have a clean template, it's currently quite messy.

Not started with the wifi scanner script yet.

### Worked hours

Forgot to keep track but quite some hours. had a mistake in NetworkScannerScapy and took long to figure it out. I would say around 6 to 8 hours.

## Deadline 4

### Scripts

Changed all current output to json output so that it fits nicely in the browser output, and thus I can clean up the html template.

Put in an alternative to ARP host discovery, ARP seemed unreliable.

Retried os detection with nmap, this time successful and reliable output.

Not gotten around to implementing the keylogger website of les 9 yet. Tried implementing a path finder for domains but seems to be complicated and I've put it off for now.

### Worked hours

So far 8h for all, cleaned up some code here and there.

## Questions answered - report

1. **What is ethical/white-hat hacking?**
   Ethical or white-hat hacking, in my opinion, is an incredibly valuable practice in the cybersecurity world. It involves skilled individuals intentionally probing computer systems, networks, or applications to uncover vulnerabilities, but they do so with the owner's permission. This practice is widely recognized for enhancing cybersecurity and safeguarding systems against malicious attacks.
2. **In what context does this happen?**
   Ethical hacking takes place within the broader context of cybersecurity. Organizations hire ethical hackers to assess the security of their systems, and it's critical that this is done legally and ethically.
3. **What are the basic requirements for ethical hacking?**
   In my view, to become an ethical hacker, you need a solid foundation in computer systems, programming, networking, and cybersecurity principles. Equally important is obtaining permission from the system owner and following strict ethical guidelines and legal regulations.
4. **What is pentesting?**
   Penetration testing, or pentesting, is, in my opinion, a crucial aspect of cybersecurity. It involves simulating cyberattacks on systems to discover vulnerabilities. The ultimate goal is to evaluate and improve a system's security posture.
5. **What are the different phases described in the literature, specifically under "reconnaissance"? Describe!**
   In the realm of cybersecurity, the reconnaissance phase is an essential part of the process. During this phase, hackers gather information about the target system, such as IP addresses, domain names, and network configurations. This information is invaluable for planning a successful attack.
6. **What is bug bounty? What are the opportunities for participating in bug bounty programs?**
   Bug bounty programs provide opportunities for ethical hackers to contribute to cybersecurity while earning rewards. These programs allow participants to find and report security vulnerabilities in exchange for monetary compensation, recognition, or even swag. It's an exciting and mutually beneficial initiative.
7. **How does the Belgian Intigriti (intigriti.com) platform relate to this?**
   Intigriti's bug bounty platform serves as a bridge between organizations and security researchers. It offers opportunities for ethical hackers to engage with organizations, identify vulnerabilities, and receive rewards for their efforts. It's a win-win situation for both parties involved.
8. **How do you proceed with bug bounty? What is the best approach for a beginner bounty hunter?**
   Getting started with bug bounty requires a structured approach. Beginners should first gain a strong foundation in cybersecurity basics and ethical hacking. Then, they should select a bug bounty platform, carefully read the guidelines, and start with targets that match their skill level. Patience is key, and networking with experienced hunters can provide valuable insights and guidance for success.
