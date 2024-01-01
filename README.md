# Ethical Hacking Final Project

This project's scope was to make a project that you could use for bounty hunting and possibly pentesting.

## Scripts

* Domain analysing `<url based>`

  * Location
  * response headers
  * DNS Sec validation
  * WHOIS information
* Find status of popular ports of a specific target - bigger port search range `<IPv4 based>`
* Network scan `<IPv4 & subnet range based>`

  * Find active hosts on network
  * Find open ports of targets
  * Find Operation System information of targets
* MITM attack, ARP poisoning `<Do not use this lightly>`
* TCP traffic sniffer for user and password credentials `<2 possible ports based>`

  * This script might not be optimized as I realized that this would be unlikely to be functional in practical situations
* Web HTML login bruteforce `<Do not use this lightly>`

  * There is a script in the root of this repo that will set up an example website for testing and validating functionality
* SSH bruteforcer `<Do not use this lightly>`

  * Script was tested and validated on a virtual machine SSH connection.

## Output

I started with the idea to make all output go both to CLI aswell as displayed in the HTML however due to being short on time and SSH bruteforcer messing up the CLI I decided to discontinue CLI output, I did leave the CLI input in those that I already implemented in to.

All functions now generate a file with function name + execution date in the filename so that it will always be unique. Results to be found in 'results' directory.

## Starting the program

First you will need a new python environment with the right installed libraries. So let's start with making a new virtual environment:

```bash
python -m venv /path/to/NewVenv
```

Then activate the virtual environment:

```bash
/path/to/NewVenv/Scripts/activate
```

Now install the libraries for this program:

```bash
pip install -r ./requirements.txt
```

Starting up the main program - this will launch a flask website for easier usage.

```bash
python main.py
```

### Starting up the basic Webserver for bruteforcer testing

Simply execute the following command and then head over to [http://127.0.0.1:5005](http://127.0.0.1:5005)

```bash
python simpleLogin.py
```
