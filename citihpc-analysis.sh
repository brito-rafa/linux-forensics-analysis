#!/bin/bash
#CitiHPC Forensic Analysis
#Written by Kushal Mall
      

TODAY=`date +%y%m%d`
NOW=`date +%y%m%d-%H%M%S`

# Asssigning Color Codes
red='\e[0;31m'
green='\e[0;32m'
blue='\e[1;34m'
NC='\e[0m'


user=`id | awk 'BEGIN { FS="("} { print $2}' | awk 'BEGIN { FS=")"} {print $1}'`
echo -e "${green} Info: User $user is executing the script ${NC}"

# Parsing command line parameters
# Checking for data files from forensic script
if [[ -z "$1" ]]; then 
	echo -e "${red} Usage: $0 <citihpc-forensic-data-directory>.Specifiy the path of the data directory. ${NC}"
	exit 1
else
	if [ -d $1 ]; then
		MYDATADIR=$1
	else
		echo -e "${red} Error: could not open data directory $1 ${NC}"
		exit 2
	fi
        VERBOSE=0
        if [[ -n "$2" ]]; then 
                if [ "$2" = "-v" ]; then 
                        VERBOSE=1
                        echo -e "${green} Info: Verbose Mode is ON ${NC}"
                fi
        fi

fi

# Checking for presence of Static Files
STATIC=`ls ${MYDATADIR}/static* 2>/dev/null | head -1 2>/dev/null`

if [ ! -f "$STATIC" ]; then 
        echo -e "${red} Error: Could not find static file on $MYDATADIR data directory ${NC}"
        exit 3
fi

sysinfo=`grep -A1 "Info: uname -a" $STATIC | sed -n '2,2p'`
echo -e "${green} Info: Starting Citi HPC Low Latency Analysis v1.16 on $TODAY at $NOW ${NC}"
echo -e "${green} Info: System Specifications: $sysinfo"


if [ $VERBOSE -eq 1 ]; then 
	echo -e "${green} Info: 30 Parameters relevant to Low Latency will be checked during the analysis ${NC}"
	echo -e "${green} Info: Data directory is $MYDATADIR ${NC}"
	echo -e "${green} Info: Checking for presence of Dynamic Data Files ${NC}"
fi 

FIRSTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | head -1 2>/dev/null`
LASTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | tail -2 | head -1`
ALLDYNAMIC=`ls ${MYDATADIR}/dynamic*gz`

compress=`ls ${MYDATADIR}/dynamic*gz | wc -l `
term_collector=()
if [ $compress -lt 2 ]; then 
	echo -e "${red} Error: Dynamic Files cannot be found or are not compressed!! ${NC}"
	exit 6
fi 

if [ ! -f "$FIRSTDYNAMIC" ]; then 
        echo -e "${red} Error: Could not find dynamic file on $MYDATADIR data directory ${NC}"
        exit 4
fi

if [ ! -z "$LASTDYNAMIC" ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${green} Info: Dynamic File Found .. variable assigning in progress ${NC}"
	fi 
else 
	echo -e "${green} Info: Dynamic file not exisiting please check !! ${NC}"
fi

if [ ! -f "$LASTDYNAMIC" ]; then 
	echo -e "${red} Error: Could not find last dynamic file on $MYDATADIR data directory ${NC}"
	exit 5
fi


if [ $VERBOSE -eq 1 ]; then 
	echo -e "${green} Info: Found $FIRSTDYNAMIC as first dynamic file ${NC}"
	echo -e "${green} Info: Found $LASTDYNAMIC as last dynamic file ${NC}"
fi


echo -e "${green} Info: Starting Static Data Analysis ${NC}"

# Finding RHEL Release
rhel=0
rhel_release=`grep -P '^Red\sHat.*6\.\d?' $STATIC | head -1`
if [[ "$rhel_release" =~ [/Santiago/] ]]; then
        let rhel="6"
else
        let rhel="5"
fi
#echo " RHEL Version: $rhel"

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for presence of Logical Volumes ${NC}"
fi
if ! grep -q "Logical volume" $STATIC; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Logical Volume Not Present ${NC}"
	else
			term_collector+=('Logical Volume Manager is not in use. This can indicate that the system is not running the LLP build.')
	fi
fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for presence of Hyper-Threading ${NC}"
fi

cpu=`grep "cpu cores" $STATIC | uniq -d | awk '{print $4}'`
sibling=`grep "siblings" $STATIC | uniq -d | awk '{print $3}'`

if [ "$cpu" -ne "$sibling" ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Hyper-threading Detected -- Not Recommended for Low Latency Environment ${NC}"
	else 
			term_collector+=('Hyper-threading(HT)is enabled.HT is not recommended for low latency due to jitter.')
	fi
fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for uniform memory speed ${NC}"
fi

speedcnt=`grep -A17 "Memory Device" $STATIC | grep -e Speed  |grep -vi "Unknown"| uniq -d | awk '{print $2}' | wc -l`

if [ $speedcnt -gt 1 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Speed is not uniform across memory devices ${NC}"
	else
			term_collector+=('Memory Speed is not uniform across the memory devices which may result in performance degradation.')
	fi
fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for uniform memory size ${NC}"
fi

uniformmem=`grep -A17 "Memory Device" $STATIC | grep -e Size | grep -v "No"|  sort | uniq -d | wc -l`

if [ $uniformmem -gt 1 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Memory Size Not Uniform ${NC}"
		else
			term_collector+=('Non uniform memory size has been detected which may lead to unpredictable speed and memory access.')
	fi
fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for Broadcom NIC Interface ${NC}"
fi

ch=0
arr2=()
arr1=(`grep "Ring parameters"  $STATIC | awk '{print $4}'| sed -e 's/://g'`)
for ((i=0; i< ${#arr1[@]};i++)); do
	arr2+=(${arr1[i]})
	let ch=ch+1
done    

arr3=(`grep  -e "Broadcom" $STATIC | awk '{print $3}' | grep ^eth | sed 's/://g'`)

# Broadcom check for IBM Servers
if grep -q "Vendor: IBM Corp." $STATIC; then
for ((i=0;i<${#arr2[@]};i++)); do
        for ((j=0;j<${#arr3[@]};j++)); do
                if [ "${arr2[i]}" ==  "${arr3[j]}" ]
                        then
				if [ $VERBOSE -eq 1 ]
					then                                   
	                        	       echo -e "${red} Warning: Broadcom NIC detected for interface ${arr3[j]}.Not a Recommended NIC Vendor. ${NC}"
					else
					       term_collector+=('Broadcom NIC has been detected in the system.Not a favoured vendor for LLP')
				fi
                 fi
        done
done
fi

#Broadcom for HP Servers
if grep -q "Vendor: HP" $STATIC; then
arr_hp=()
arr_hp1=()
arr_hp=(`grep "Ring parameters" $STATIC | awk '{print $4}'`)
arr_hp1=(`grep "Broadcom" $STATIC | awk '{print $1}'`)
for ((i=0;i<${#arr_hp[@]};i++)); do
	for ((j=0;j<${#arr_hp1[@]};j++)); do
		 if [ "${arr_hp[i]}" ==  "${arr_hp1[j]}" ]
                        then
				if [ $VERBOSE -eq 1 ]
					then 
                        		       echo -e "${red} Warning: Broadcom NIC detected for interface ${arr_hp[i]}. Not a recommended NIC Vendor. ${NC}"
				else
					       term_collector+=('Network interface is using a Broadcom chip set which is not recommended for low latency.')	
				fi
		 fi
	done
done
fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for sysctl Parameters ${NC}"
fi
sys_ref_para=()
sys_ref_val=()
sys_actual_para=()
sys_actual_val=()
sys_var1=0
sys_var2=0
sys_parameter=`cat kernellog.txt | awk  '{print $1}'`
sys_value=`cat kernellog.txt | awk  '{print $3}'`
for i in $sys_parameter; do
	sys_ref_para[sys_var1]=`echo $i`
	let sys_var1=sys_var1+1
done
for i in $sys_value; do
	sys_ref_val[sys_var2]=`echo $i`
	let sys_var2=sys_var2+1
done
for((i=0; i<${#sys_ref_para[@]};i++)); do
	if grep -q -w -e ${sys_ref_para[i]} $STATIC; then 
		sys_actual_para[i]=`grep -w -e ${sys_ref_para[i]} $STATIC | awk '{print $1}'`
	else 
		echo -e "${red} Kernel Parameters Not Present. Please Check the files produced from the Forensic Script!! ${NC}"
	break
	fi
done
for((i=0; i<${#sys_ref_para[@]};i++)); do
	sys_actual_val[i]=`grep -w -e ${sys_ref_para[i]} $STATIC | awk '{print $3}'`
done
for ((i=0; i<${#sys_actual_para[@]};i++)); do
        if [ "${sys_actual_val[i]}" != "${sys_ref_val[i]}" ]; then 
  			if [ $VERBOSE -eq 1 ]; then 
				echo -e "${red} Warning: Parameter mismatch for: ${sys_actual_para[i]}. Value detected: ${sys_actual_val[i]}. Actual Value Expected: ${sys_ref_val[i]} ${NC}"
			else 
				term_collector+=('Kernel Parameters are not finely tuned for low latency.')
			fi
        fi
done

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for Ring Parameters ${NC}"
fi
arr=(`grep ^Ring $STATIC | awk '{print $4}'| sed "s/://g" | grep -v ethconf | grep -v ethtool | uniq`)
COUNTER=0
if [ "${arr[$COUNTER]}" != "" ]; then
	while [  $COUNTER -lt ${#arr[*]} ]; do

		max_RX=`grep -A10 "Ring parameters for ${arr[$COUNTER]}" $STATIC | grep RX: | head -1 | awk '{print $2}'`
		current_RX=`grep -A10 "Ring parameters for ${arr[$COUNTER]}" $STATIC | grep RX: | tail -1 | awk '{print $2}'`
		if [ "$max_RX" -ne "$current_RX" ] 
			then
#			echo -e "${green} Info: Current Settings for RX :$current_RX ${NC}" 
				if [ $VERBOSE -eq 1 ]
					then 
			    			echo -e "${red} Warning: Check RX Ring Buffer settings for interface ${arr[$COUNTER]}. Current Settings: $current_RX. Maximum Settings: $max_RX ${NC}"
				else
						term_collector+=('The receive ring buffer is not set to the maximum. This can lead to packet drops.')

				fi
		fi
		max_TX=`grep -A10 "Ring parameters for ${arr[$COUNTER]}" $STATIC | grep TX: | head -1 | awk '{print $2}'`
		current_TX=`grep -A10 "Ring parameters for ${arr[$COUNTER]}" $STATIC | grep TX: | tail -1 | awk '{print $2}'`
		if [ $max_TX -ne "$current_TX" ]; then 
			if [ $VERBOSE -eq 1 ]; then 
				echo -e "${red} Warning: Check TX Ring Buffer settings for interface ${arr[$COUNTER]}. Current Settings: $current_TX. Maximum Settings:$max_TX ${NC}"
				else 
				term_collector+=('The receive ring buffer is not set to the maximum. This can lead to packet drops.')
			fi
		fi              
             	let COUNTER=COUNTER+1
    	done
fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking whether TCP Segmentation Offload is Off ${NC}"
fi
tcpseg=(`grep tcp-segmentation-offload $STATIC | awk '{print $2}'`)
for ((i=0; i< ${#tcpseg[@]};i++)); do
	if [ "${tcpseg[i]}" != "on" ]; then
		if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: TCP Segmentation Offload is Off ${NC}"		
		else
			term_collector+=('TCP Segmentation Offload is disabled which can lead to higher CPU utilization.')
		fi
	fi
done

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking whether Generic Segmentation is Off ${NC}"
fi
genseg=(`grep generic-segmentation-offload: $STATIC | awk '{print $2}'`)
for ((i=0; i< ${#genseg[@]};i++)); do
	if [ "${genseg[i]}" != "on" ]; then
		if [ $VERBOSE -eq 1 ]; then
			echo -e "${red} Warning: Generic Segmentation is Off ${NC}"
		else 
			term_collector+=('Generic Segmentation Offload is disabled which can lead to higher CPU utilization.')	
		fi
	fi
done

# ASU Analysis
if grep -q "Vendor: IBM Corp." $STATIC; then
	echo -e "${green} Info: Performing ASU Analysis Check ${NC}"
	asu_ref_para=()
	asu_ref_val=()
	asu_actual_para=()
	asu_var1=0
	asu_var2=0
	asu_actual_val=()
	asu_parameter=`cat ibm-asu-llp-base.txt | awk  '{print $1}' | sed -e 's/=/ = /g' | awk '{print $1}'`
	asu_value=`cat ibm-asu-llp-base.txt | awk  '{print $1}' | sed -e 's/=/ = /g' | awk '{print $3}'`
		for i in $asu_parameter; do
			asu_ref_para[asu_var1]=`echo $i`
			let asu_var1=asu_var1+1
		done
		for i in $asu_value; do
			asu_ref_val[asu_var2]=`echo $i`
			let asu_var2=asu_var2+1
		done
		for((i=0; i<${#asu_ref_para[@]};i++)); do 
			if grep -q -w -e ${asu_ref_para[i]} $STATIC; then 
				asu_actual_para[i]=`grep -w -e ${asu_ref_para[i]} $STATIC | awk '{print $1}' | sed 's/=/ = /g' | awk '{print $1}'`
			else
				echo -e "${red} Warning: ASU Parameters not present. Please check the static files produced from the Forensic Script !!"
			break
			fi 
		done
		for((i=0; i<${#asu_ref_para[@]};i++)); do
			asu_actual_val[i]=`grep -w -e ${asu_ref_para[i]} $STATIC | awk '{print $1}' | sed 's/=/ = /g' | awk '{print $3}'`
		done
		for ((i=0; i<${#asu_actual_para[@]};i++)); do 
		        if [ "${asu_actual_val[i]}" != "${asu_ref_val[i]}" ]; then 
				if [ $VERBOSE -eq 1 ]; then 
	                        	echo -e "${red} Warning: Parameter mismatch for: ${asu_actual_para[i]}. Value detected: ${asu_actual_val[i]}. Actual Value Expected: ${asu_ref_val[i]} ${NC}"
			else
					term_collector+=('BIOS settings are not optimized for low latency.')
				fi
		        fi
		done
fi

# Conrep Analysis
conrep=`ls  ${MYDATADIR}/conrepxml* 2>/dev/null | head -1`
if [ "$conrep" !=  "" ] && [ -f $conrep ]; then
	echo -e "${green} Info: Conrep config file detected. Proceeding with conrep analysis.. ${NC}"
	conrep=`ls ${MYDATADIR}/conrepxml* | head -1`
	ref_parameter=()
	ref_value=()
	actual_value=()
	var1=0
	var2=0
	parameter=`cat conrep.config | awk  '{print $1}'`
	value=`cat conrep.config | awk  '{print $3}'`

	for i in $parameter; do
		ref_parameter[var1]=`echo $i`
		let var1=var1+1
	done

	for i in $value; do
		ref_value[var2]=`echo $i`
		let var2=var2+1
	done
	for((i=0; i<${#ref_parameter[@]};i++)); do 
		actual_value[i]=`grep -w -e ${ref_parameter[i]} $conrep | awk -F\"\> '{print $2}' | awk -F\<\/ '{print $1}'`
	done
	for ((i=0; i<${#ref_value[@]};i++)); do 
		if [ "${ref_value[i]}" != "${actual_value[i]}" ]; then
			if [ $VERBOSE -eq 1 ]; then
				echo -e "${red} Warning: Parameter mismatch for ${ref_parameter[i]}. Value Detected: ${actual_value[i]}. Actual Value Expected: ${ref_value[i]} ${NC}"
			else
				term_collector+=('BIOS settings are not optimized for low latency.')	
			fi
		fi
	done
fi
 
echo -e "${green} Info: End of Static Data Analysis ${NC}"

echo -e "${green} Info: Starting Dynamic Data Analysis ${NC}"

if [ $VERBOSE -eq 1 ]
then
	echo -e "${blue} Debugging... Checking for TCP Segment Retransmission ${NC}"
fi
	tcp1=`zgrep -A8 -e "Tcp"  $FIRSTDYNAMIC | head | sed -n '9,9p' | awk '{print $1}'`

	tcp2=`zgrep -A8 -e "Tcp"  $LASTDYNAMIC | head | sed -n '9,9p' | awk '{print $1}'`

if [ $tcp1 -lt $tcp2 ]
then 
	dif=`expr $tcp2 - $tcp1`
	if [ $VERBOSE -eq 1 ]
		then 
			echo -e "${red} Warning: TCP Segment Retransmission Detected with a packet difference of $dif ${NC}"
	else 
			term_collector+=('TCP Segment Retransmission detected which may indicate network degradation.')
	fi
else
	dif=`expr $tcp1 - $tcp2`
	if [ $VERBOSE -eq 1 ]
		then 
			echo -e "${red} Warning: TCP Segment Retransmission Detected with a packet difference of $dif ${NC}"
	else 
			term_collector+=('TCP Segment Retransmission detected which may indicate network degradation.')
	fi
fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for UDP Packet Received Errors ${NC}"
fi
udp1=`zgrep -A3 -e "Udp" $FIRSTDYNAMIC | head | sed -n '4,4p' | awk '{print $1}'`
udp2=`zgrep -A3 -e "Udp" $LASTDYNAMIC | head | sed -n '4,4p' | awk '{print $1}'`
if [ $udp1 -lt $udp2 ]; then 
	udpdiff=`expr $udp2 - $udp1`
else
	udpdiff=`expr $udp1 - $udp2`
fi
if [ $udpdiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
		echo -e "${red} Warning: UDP Packet Received Error detected with a packet difference of $udpdiff ${NC}"
	else 
		term_collector+=('UDP Packet Received Errors detected which may indicate network degradation.')
	fi
fi


if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for TCP Data Loss Event ${NC}"
fi
	tcpd1=`zgrep -A11 -e "TcpExt" $FIRSTDYNAMIC | sed -n '12,12p' | awk '{print $1}'`
	tcpd2=`zgrep -A11 -e "TcpExt" $LASTDYNAMIC | sed -n '12,12p' | awk '{print $1}'`
if [ $tcpd1 -lt $tcpd2 ]; then 
	datadiff=`expr $tcpd2 - $tcpd1`
else 
	datadiff=`expr $tcpd1 - $tcpd2`
fi
if [ $datadiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
		echo -e "${red} Warning: TCP Data Loss detected with a difference of $datadiff bytes ${NC}"
	else 
		term_collector+=('TCP Data Loss detected which may indicate network degradation.')
	fi
fi

if [ $VERBOSE -eq 1 ]; then 
        echo -e "${blue} Debugging... Checking for TCP Time-Out ${NC}"
fi
	timed1=`zgrep -A12 -e "TcpExt" $FIRSTDYNAMIC | sed -n '13,13p' | awk '{print $1}'`
	timed2=`zgrep -A12 -e "TcpExt" $LASTDYNAMIC | sed -n '13,13p' | awk '{print $1}'`
if [ $timed1 -lt $timed2 ]; then 
	timediff=`expr $timed2 - $timed1`
else
	timediff=`expr $timed1 - $timed2`
fi
if [ $timediff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
		echo -e "${red} Warning: TCP Time-Out detected with a difference of $timediff ${NC}"
	else 
		term_collector+=('TCP Time-Out has been detected which may indicate network degradation.')
	fi
fi


#if [ $VERBOSE -eq 1 ]; then 
#	echo -e "${blue} Debugging... Printing all active interfaces ${NC}"
#		for ((i=0; i< ${#arr2[@]};i++));do
#			echo ${arr2[i]}
#		done
#fi

if [ $VERBOSE -eq 1 ]; then 
	echo -e "${blue} Debugging... Checking for Error Frame Drop for TX and RX interfaces ${NC}"
fi	

for ((i=0; i< ${#arr2[@]};i++));do

#Checking for RX errors
rx_err1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "RX packets" | awk '{print $3}'| sed -e 's/errors://g'`
rx_err2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "RX packets" | awk '{print $3}'| sed -e 's/errors://g'`
if [ $rx_err1 -lt $rx_err2 ]; then 
	rx_errordiff=`expr $rx_err2 - $rx_err1`
else
	rx_errordiff=`expr $rx_err1 - $rx_err2`
fi

if [ $rx_errordiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
		echo -e "${red} Warning: Error Frame difference of $rx_errordiff bytes detected for RX interface ${arr2[i]} ${NC}"
	else 
		term_collector+=('Frame Error on RX Interface indicating ethernet card congestion and network degradation')
	fi
fi

#Checking for TX errors
tx_err1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "TX packets" | awk '{print $3}'| sed -e 's/errors://g'`
tx_err2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "TX packets" | awk '{print $3}'| sed -e 's/errors://g'`
if [ $tx_err1 -lt $tx_err2 ]; then 
        tx_errordiff=`expr $tx_err2 - $tx_err1`
else
        tx_errordiff=`expr $tx_err1 - $tx_err2`
fi
if [ $tx_errordiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
		        echo -e "${red} Warning: Error Frame difference of $tx_errordiff bytes detected for TX interface ${arr2[i]} ${NC}"
	else
			term_collector+=('Frame Error on TX Interface indicating ethernet card congestion and network degradation')
	fi
fi

#Checking for RX drop
rx_drop1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "RX packets" | awk '{print $4}'| sed -e 's/dropped://g'`
rx_drop2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "RX packets" | awk '{print $4}'| sed -e 's/dropped://g'`
if [ $rx_drop1 -lt $rx_drop2 ]; then 
		rx_dropdiff=`expr $rx_drop2 - $rx_drop1`
else
		rx_dropdiff=`expr $rx_drop1 - $rx_drop2`
fi

if [ $rx_dropdiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Drop difference of $rx_dropdiff bytes detected for RX interface ${arr2[i]} ${NC}"
	else
			term_collector+=('Drop Difference for RX Interface indicating ethernet card congestion and network degradation')
	fi
fi

#Checking for TX drop
tx_drop1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "TX packets" | awk '{print $4}'| sed -e 's/dropped://g'`
tx_drop2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "TX packets"| awk '{print $4}'| sed -e 's/dropped://g'`
if [ $tx_drop1 -lt $tx_drop2 ]; then 
                tx_dropdiff=`expr $tx_drop2 - $tx_drop1`
else
                tx_dropdiff=`expr $tx_drop1 - $tx_drop2`
fi
if [ $tx_dropdiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
		        echo -e "${red} Warning: Drop difference of $tx_dropdiff bytes detected for TX interface ${arr2[i]} ${NC}"
	else
			term_collector+=('Drop Difference for TX Interface indicating ethernet card congestion and network degradation')
	fi
fi


#Checking for RX Overrun
rx_run1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "RX packets" | awk '{print $5}'| sed -e 's/overruns://g'`
rx_run2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "RX packets" | awk '{print $5}'| sed -e 's/overruns://g'`
if [ $rx_run1 -lt $rx_run2 ]; then 
	rx_rundiff=`expr $rx_run2 - $rx_run1`
else
	rx_rundiff=`expr $rx_run1 - $rx_run2`
fi

if [ $rx_rundiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Overrun difference of $rx_rundiff bytes detected for RX interface ${arr2[i]} ${NC}"
	else
			term_collector+=('Overrun Detected for RX Interface indicating ethernet card congestion and network degradation')
	fi
fi

#Checking for TX overrun
tx_run1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "TX packets" | awk '{print $5}'| sed -e 's/overruns://g'`
tx_run2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "TX packets" | awk '{print $5}'| sed -e 's/overruns://g'`
if [ $tx_run1 -lt $tx_run2 ]; then 
        	tx_rundiff=`expr $tx_run2 - $tx_run1`
	else
        	tx_rundiff=`expr $tx_run1 - $tx_run2`
fi
if [ $tx_rundiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
		        echo -e "${red} Warning: Overrun  difference of $tx_rundiff bytes detected for TX interface ${arr2[i]} ${NC}"
	else
			term_collector+=('Overrun Detected for TX Interface indicating ethernet card congestion and network degradation')
	fi
fi

#Checking for RX Frame
rx_frame1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "RX packets" | awk '{print $6}'| sed -e 's/frame://g'`
rx_frame2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "RX packets" | awk '{print $6}'| sed -e 's/frame://g'`

if [ $rx_frame1 -lt $rx_frame2 ]; then 
	rx_framediff=`expr $rx_frame2 - $rx_frame1`
else
	rx_framediff=`expr $rx_frame1 - $rx_frame2`
#echo -e "${red} Warning: Difference in RX Frame Detected for interface ${arr2[i]}:$rx_framediff ${NC}"
fi

if [ $rx_framediff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Frame difference of $rx_framediff bytes detected for the RX interface ${arr2[i]} ${NC}"
	else
			term_collector+=('Frame Difference Detected for RX Interface indicating ethernet card congestion and network degradation')
	fi
fi

#Checking for TX Carrier
tx_carrier1=`zgrep -A6 "^${arr2[i]}      Link encap" $FIRSTDYNAMIC | zgrep "TX packets" | awk '{print $6}'| sed -e 's/carrier://g'`
tx_carrier2=`zgrep -A6 "^${arr2[i]}      Link encap" $LASTDYNAMIC | zgrep "TX packets" | awk '{print $6}'| sed -e 's/carrier://g'`

if [ $tx_carrier1 -lt $tx_carrier2 ]; then 
        tx_carrierdiff=`expr $tx_carrier2 - $tx_carrier1`
else
        tx_carrierdiff=`expr $tx_carrier1 - $tx_carrier2`
fi

if [ $tx_carrierdiff -gt 0 ]; then 
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Carrier difference of $tx_carrierdiff bytes detected for interface ${arr2[i]} ${NC}"
	else
			term_collector+=('Carrier Difference detected for TX Interface indicating ethernet card congestion and network degradation')
	fi
fi
done

# Checking for Server Swapping 

if [ $VERBOSE -eq 1 ]; then 
        echo -e "${blue} Debugging... Checking for Server Swap ${NC}"
fi
server_swap=`zgrep -A4 "Info: free ..." $ALLDYNAMIC | sed -n '5,5p' | awk '{print $3}'`
if [ $server_swap -ne 0 ]; then 
#	echo -e "${green} Info: No Server Swapping ${NC}"
#else
	if [ $VERBOSE -eq 1 ]; then 
			echo -e "${red} Warning: Server Swapping Detected with a current usage of $server_swap bytes. Please refer Memory Heat Map. ${NC}"
	else 
			term_collector+=('Memory Swapping has been detected which could cause severe performance degradation.')
	fi
fi

if [ $VERBOSE -eq 1 ]; then 
        echo -e "${blue} Debugging... Checking for CPU Idle State ${NC}"
fi
corecount=`grep  ^processor $STATIC | tail -1 | awk '{print $3}'`
let cpu_core=corecount+2
mygrep="-A"$cpu_core

# Checking for CPU Idle State for Servers running RHEL 6
if [ "$rhel" = "6" ]; then
	star_ibm=()
	cpu_ibm=()
	count_ibm=0
	star_ibm=`zgrep $mygrep "%idle" $ALLDYNAMIC | grep "Average:" | awk '{print $11}'`
		for i in $star_ibm; do
			cpu_ibm[count_ibm]=`echo $i`
			let count_ibm=count_ibm+1
		done
		for((i=0; i<${#cpu_ibm[@]};i++)) do
			if [ "${cpu_ibm[i]}" = "%idle" ]; then 
        			cpu_ibm[$i]=10
			fi
		done
		for ((i=0; i< ${#cpu_ibm[@]};i++)) do
			if [[ "${cpu_ibm[i]}" < "1" ]];then
				if [ $VERBOSE -eq 1 ]; then 
				       echo -e "${red} Warning: CPU Starvation Detected:${cpu_ibm[i]}.Please check CPU Heat Map. ${NC}"
				else
					term_collector+=('High CPU Utilization detected.')
				fi
			break
			fi
		done
fi

# Checking CPU Idle state for Servers running RHEL 5
if [ "$rhel" = "5" ]; then 
	star_hp=()
	cpu_hp=()
	count_hp=0
	star_hp=`zgrep $mygrep "%idle" $ALLDYNAMIC | grep "Average:" | awk '{print $8}'`
		for i in $star_hp; do
			cpu_hp[count_hp]=`echo $i`
			let count_hp=count_hp+1
		done

		for((i=0; i<${#cpu_hp[@]};i++)) do
			if [ "${cpu_hp[i]}" = "%idle" ]
			then
			        cpu_hp[$i]=10
			fi
		done
		for ((i=0; i< ${#cpu_hp[@]};i++)) do
			if [[ "${cpu_hp[i]}" < "1" ]];then 
				if [ $VERBOSE -eq 1 ]; then 
				       echo -e "${red} Warning: CPU less than 10% idle has been detected. Please check CPU Heat Map. ${NC}"
				else 
					term_collector+=('High CPU Utilization detected.')
				fi
			break
			fi
		done
fi

# Checking for Excessive Content Switching
if [ $VERBOSE -eq 1 ]; then 
        echo -e "${blue} Debugging... Checking for content switching ${NC}"
fi
content=0
if [ "$rhel" = "6" ]; then
	bottle=0
	nd=()
	bottle_neck=()
	nd=`zgrep -A1 "cswch/s" $ALLDYNAMIC | awk '{print $4}' | sed -e 's/cswch\/s/ /g'`
		for i in $nd; do
			bottle_neck[bottle]=`echo $i`
			let bottle=bottle+1
		done
		for ((i=0; i<${#bottle_neck[@]} ;i++)) do
			if [[ "${bottle_neck[i]}" > "3000" ]]; then 
				let content=content+1
			fi
		done
	if [ $VERBOSE -eq 1 ]; then 
		echo -e "${red} Warning: $content instances of Context Switching has been detected ${NC}"
	else
		term_collector+=('Context Switching')
	fi
fi

content=0
if [ "$rhel" = "5" ]; then
	bottle=0
	nd=()
	bottle_neck=()
	nd=`zgrep -A1 "cswch/s" $ALLDYNAMIC | awk '{print $3}' | sed -e 's/cswch\/s/ /g'`
		for i in $nd; do
			bottle_neck[bottle]=`echo $i`
			let bottle=bottle+1
		done
		for ((i=0; i<${#bottle_neck[@]} ;i++)) do
			if [[ "${bottle_neck[i]}" > "3000" ]]; then 
		        	let content=content+1
			fi
		done
	if [ $VERBOSE -eq 1 ]; then 
		echo -e "${red} Warning: $content instances of Context Switching has been detected ${NC}"
	else
		term_collector+=('Context Switching')
	fi
fi

#sar Parameter Check -- Disk Bottleneck Check

function disk_utilization_check {
	line_cnt=0
	line_cnt=`zcat $FIRSTDYNAMIC | grep "Average:" | sed -n '/DEV/,/IFACE/ p' | wc -l`
	let ll=line_cnt-2
	sr="-A"$ll
	sar_dev=`zcat $ALLDYNAMIC | grep  "Average:" | grep $sr "DEV" | awk '{print $2}'| sed -e 's/DEV//g'`
	sar_await=`zcat $ALLDYNAMIC | grep  "Average:" | grep $sr "DEV" | awk '{print $8}' | sed -e 's/await//g'`
	sar_util=`zcat $ALLDYNAMIC | grep  "Average:" | grep $sr "DEV" | awk '{print $10}' | sed -e 's/%util//g'`
	sar_tim=`zcat $ALLDYNAMIC | grep $sr "DEV" | grep -P '\d\d:\d\d:\d\d\s' | awk '{print $1}'`
	pp=0
	dev_chk=()
		for i in $sar_dev; do
		        dev_chk[pp]=`echo $i`
	        	let pp=pp+1
		done
	stamp=0
	sar_stamp=()
		for i in $sar_tim; do
	        	sar_stamp[stamp]=`echo $i`
	        	let stamp=stamp+1
		done

	disk_anomaly=0
	tim=0
	await_chk=()
		for i in $sar_await; do
	        	await_chk[tim]=`echo $i`
	        	let tim=tim+1
		done
		for ((i=0;i<${#await_chk[@]};i++)) do
        		if [[ "${await_chk[i]}" > "2.00" ]]; then
				let disk_anomaly=disk_anomaly+1
		        fi
		done
	ut=0
	util_chk=()
		for i in $sar_util; do
		        util_chk[ut]=`echo $i`
		        let ut=ut+1
		done
		for ((i=0;i<${#util_chk[@]};i++)) do
		        if [[ "${util_chk[i]}" > "20.00" ]]; then
				let disk_anomaly=disk_anomaly+1
		        fi
		done

	if [ $VERBOSE -eq 1 ];then 
        		 echo -e "${red} Warning: Anomaly Detected for Disk:$disk_anomaly ${NC}"
	         else
        	         term_collector+=('High disk utilization detected')
	fi
}

#disk_utilization_check
echo -e "${red} Warning: Following Sub Optimal Configurations have been detected in the system:"
for ((i=0; i< ${#term_collector[@]};i++));do
	echo " ${term_collector[i]}" 
done | sort | uniq

echo -e " Please Contact SA for help!. For technical details execute the script in Verbose mode (-v). Thank You. ${NC}"

# Heatmaps Generation
echo -e "${green} Info: Creating heatmap files... ${NC}" 
./genheatmaps.pl ${MYDATADIR}
echo -e "${green} Info: End of dynamic data analysis ${NC}"

