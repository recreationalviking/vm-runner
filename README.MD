# What this code does:
1.	Retrieve malware sample metadata file
1.	Verify necessary fields within metadata file (scan info and file extension)
1.	Validate corresponding malware sample file exists
1.	Revert each virtual machine to known good snapshot
1.	Start each virtual machine from snapshot
1.	Transfer malware sample to each virtual machine
1.	Verify the malware sample made to the system
1.	Run malware sample on each virtual machine
1.	Collect exit code from each run sample on each virtual machine (if possible)
1.	Collect process logs filtering for the sample name from each virtual machine (if possible)
1.	Collect application whitelisting logs from each virtual machine filtering for the sample name (if possible)
1.	Log collected data to mongo
1.	Stop the virtual machine
1.	Repeat steps until all valid samples in selection have been tested

# File Descriptions
`vm-runner/runner.py` - main app for running orchestrating the VMs and experiment\
`vm-runner/load_runner.json` - main config file\
`vm-runner/vm_control.py` - lib for controlling VirtualBox\
`vm-runner/vt_builder.py` - lib for reading AV info\
`vm-runner/data_logger.py` - data logger library for pushing things into mongo\
`vm-runner/data_parse.py` - parser script for the mongo dump to determine whitelisting effectiveness\
`vm-runner/imavirus.c` - test code - compile to test whitelisting apps\
`vm-runner/imavirus_fail.c` - test code - compile to test whitelisting apps\
`vm-runner/README.MD` - this

# Necessary sub dirs:
    vm-runner/loggerdump
    vm-runner/tmp

# Installation:
1. Install base OS, Ubuntu
1. Install virtualbox
1. Clone this repo
1. Get a copy of the VirusTotal academic database
1. Create loggerdump and tmp directories
1. Modify the vt_builder.py to reflect file locations
1. Modify the load_runner.json file to reflect necessary parameters (creds, sample numbers, etc.)
1. Test runner.py with a low number of samples configured in load_runner.json
1. Modify scripts to fit your environment
1. Run the data_parse.py on the dumped 'data' log
1. Evaluate your results!
