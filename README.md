# Suricata-Extractor
Suricata extractor is a tool to analyze the eve.json file created by Suricata and summarize some information.
Suricata extractor finds the alerts in that file and it separates them in time windows. The time window can be specified with the parameter -w.

There are three types of information summarized:

1- Alerts

On each time window the tool computes:

- The amount of alerts per severity (1,2,3,4).
- The amount of unique alerts.
- The amount of alerts per categories of alerts (as specified by the classification file of suricata).
- The amount of alerts per destination IP.
- The amount of alerts per source IP.
- The amount of alerts per destination port.

This information is stored in a json file as specified by the -j option.

2- Ports combination per time window
Also, suricata extractor computes, on each time window, some information about how the attackers attacks the ports. 

- For each time window:
    - For Each destination IP
        - For each combinations of ports attacked together, sorted by attack time. (sooner port first)
            - The amount of unique source IP addresses attacking that combination exactly.

This information is stored in a file with the same name as the json file but with the extension .ports.

3- Ports combinations at the end of the capture
- For each Destination IP
    - For each combinations of ports attacked together, sorted by attack time. (sooner port first)
        - The amount of unique source IP addresses attacking that combination exactly.

This information is stored in a file with the same name as the json file but with the extension .summary_of_ports.

Suricata extractor can read alerts from a file or from standard input.


# To read the json file in a console
If you want to visualize the json file in a console, just type:

    IFS=$'\n'; for line in `cat test.json`;do echo $line |python -m json.tool|less;done
