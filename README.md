# SocketsSurveyor

Enhancing Visibility of Your Internal Cyberspace!

SocketsSurveyor is a software application designed to enable visibility of computer network activity generated by devices as they connect from private networks to external networks or the Internet  

![alt text](https://github.com/mollensoft/sockets-surveyor/blob/master/public/Slide1.JPG)

The system works by ingesting netflow event packets generated by a local SOHO router as local devices connect through it in order to access the another network or the internet 

The system generates web based reports and email tipping to alert users when anomalous or potentially malicious network activity has been detected 

Key Use Cases:

	Are your internal/home Devices Behaving Badly?
	
	Track and Classify Outbound Network Activity per device
	
	Learn to Identify unusual device behavior through network behavior, remove troublesome devices from the internal network 
	
	Keep Track of Mobile Device Behavior and Network Activity during down hours
	
	Use as A Test Harness for Newly Purchased IOT Devices, Identify remote destinations, Network activity patterns
	
	Identify and Protect SOHO Users From Malicious Apps, Devices and Remote Systems – block high bandwidth destinations, malware C2 and Advertising trackers
	
	Validate DNS and configurations
	
	Enhance Visibility of your Internal Cyberspace

Overview:

![alt text](https://github.com/mollensoft/sockets-surveyor/blob/master/public/Slide4.JPG)

Intuitive User Interface

![alt text](https://github.com/mollensoft/sockets-surveyor/blob/master/public/Slide8.JPG)

Integrated Web Based Reports:

	Event Report – Show Enriched Destination information grouped by bytes and connection counts both high and low

	Reputation Report – Show enriched contact destination information focused on poor IP Address reputation or other enrichment sources

	Destination Ports Report – Show enriched destination port and event count information (which different ports did an internal device connect to per destination)

	Destination Reports – Show how many internal devices have contacted common Ip addresses with connection history

	Zero Days Report – Show New Destination events where contacts occurred with External Ip Addresses not previously seen in communication with Internal Devices (zero days contacts)

	Custom Date Time Query Report – Report all device contact events between two date time groups

	HTTP Outlier Report – Show events between selected internal device and external destinations where event byte count per was 5 times the Standard Deviation of the Average byte count per the selected period

Email Reports and Alerts: 

	Daily System Summary Email Report – Total Distinct Destinations added Last 24 Hours, # New Events, # Reputation 3 Events system status

	24 Hour Device Event Traffic Email Summary – Distinct Dests, Ports and orgs per internal Device last 24 Hours

	DeltaBytes Alert Email - Destinations Where Outbound Bytes Communicated Exceeded Inbound Bytes Last 2 Hours 

	Outbound Traffic Threshold Alert Email - Outbound Events occurring in the last 10 Minutes where outbound Bytes >= 1 MBs (V2 will optionally log into router and drop anomalous outbound network conns given specific configuration instructions)

	Daily Down Hours Report – Network Events between internal devices and the Internet occurring during Off Hours (typically 0100-0500)

	Daily Internal Device Report - Total Event/Byte Counts Per Internal Device and Top 500 Destinations Grouped by Each Internal Device Last 24 Hours 

![alt text](https://github.com/mollensoft/sockets-surveyor/blob/master/public/Slide17.JPG)

![alt text](https://github.com/mollensoft/sockets-surveyor/blob/master/public/Slide9.JPG)

![alt text](https://github.com/mollensoft/sockets-surveyor/blob/master/public/Slide11.JPG)

![alt text](https://github.com/mollensoft/sockets-surveyor/blob/master/public/Slide12.JPG)

