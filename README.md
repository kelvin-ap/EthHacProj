# Ethical Hacking Final Project

The objective of this project was to develop a tool suitable for both bounty hunting and potential penetration testing.

Initially, my focus was on creating a program that could analyze domains, a common practice in bounty hunting. However, my interest led me to expand the scope to include network and individual hosts as potential targets. Although I was initially hesitant about incorporating bruteforcers due to their perceived risks in school projects, curiosity got the better of me. I restricted the bruteforcer testing to my own application/VM for safety.

We were provided with ARP poisoning as a demo script, which I found intriguing during a lecture. I decided to include it in my project, but it's essential to note that the credits for this script do not belong to me.

Comparatively, I believe my scripts maintain a relatively 'friendly' approach, considering the potential lethality. Regardless, I am content with the overall structure of my code, recognizing that clean code remains an area for improvement

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

All functions that return data now generate a file with function name + execution date in the filename so that it will always be unique. Results to be found in 'results' directory.

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
