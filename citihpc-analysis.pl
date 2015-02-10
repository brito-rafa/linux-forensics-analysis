#!/usr/bin/perl -w
#
use strict;
use warnings; 

use Data::Dumper;
use Term::ANSIColor qw(:constants);
use XML::Simple;
use GD;
use GD::Graph::Data;
use GD::Graph::lines;
use GD::Graph::mixed;



# key variables
my $verbose = 0;
my $MYDATADIR; my $STATIC; my $FIRSTDYNAMIC; my $LASTDYNAMIC; my $CONREP; my $ASU;
my @LISTALLDYNAMIC;
my $HP = 0; my $IBM = 0;
my $timestamp;
my @term_collector;

my $TODAY; my $NOW;

my $hostnam; 
my $hypert; my $ht;
my $memtot; my $rhel; my $rhelminor; my $rhelcomplete;
my $numcores; my @activenics; my $total_nics; my %test_nic; my @list_disks; my $total_disks;
my $nicextralegend = "";
my $dateofdata;
my $simple; my $config_file; my @staticfile; my $lvm = 0;
my $conrep_simple; my $conrep_config;

my $graphdat; 
my $graphdatmem; 
my $graphdatnic; 
my $graphdatdiskawait; 
my $graphdatdiskcpu; 
my $graphdatdiskread; 
my $graphdatdiskwrite;
 
my %actualkernelparam; my %actualasuparam;
my %first_dynamic; my %last_dynamic;

my $verticalsize; my $horizontalsize; my $numofdynfiles;
my $verticalsizedisk;

my $compress; #number of dynamic files

my @mytype; my @mycolors; my @mytypecpu; my @mycpulegend;

# Finally executing the code
&main();

# my subroutines - main as a first
sub main {

	if (! exists $ARGV[0]) {
		&usage;
	}
	&display_header();
	&checking_datadir();
	&gettingbasicinfo();
	&reading_config();
	&parsing_static();
	# bios checking
	if ($IBM) {
		&checking_asu;
	} elsif ($HP) {
		&checking_conrep();
	}
	&compare_first_last_dynamic();
	&parsing_all_dynamic();
	&preping_data_graphs ();
        &creating_line_graph ();
        &creating_mem_graph ();
        &creating_nic_graph ();
        &creating_diskawait_graph ();
        &creating_diskcpu_graph ();
        &creating_diskread_graph ();
        &creating_diskwrite_graph ();
	&printing_analysismessages();

}

sub usage {
	print RED, "Usage: $0 <citihpc-forensic-collector-data-directory> [-v]\nSpecifiy the path of the citihpc forensic collector data directory.\n", RESET;
	exit;
}

sub display_header {

	$TODAY=`date +%y%m%d`; chomp ($TODAY);
	$NOW=`date +%y%m%d-%H%M%S`; chomp ($NOW);

	my $user=`id | awk 'BEGIN { FS="("} { print \$2}' | awk 'BEGIN { FS=")"} {print \$1}'`; chomp($user);

	print GREEN, "Info: Starting Citi HPC Low Latency Analysis on $TODAY at $NOW\n", RESET;
	print GREEN, "Info: User $user is executing the script.\n", RESET;

}

sub checking_datadir {

	if ((exists $ARGV[0]) && (-d $ARGV[0])) {
		$MYDATADIR = $ARGV[0];	
	} else {
		print RED, "Error: could not open data directory $ARGV[0] !\n", RESET;
		usage;
		exit 2;
	}

	if ((exists $ARGV[1]) && ($ARGV[1] eq "-v")) {
		$verbose=1;
		print GREEN, "Info: Verbose Mode is ON.\n", RESET;
	}

	$STATIC=`ls ${MYDATADIR}/static* 2>/dev/null | head -1 2>/dev/null`; chomp($STATIC);

	if ( ! -f $STATIC) {
		print RED, "Error: Could not find static file on $MYDATADIR data directory!\n", RESET;
		usage;
		exit 3;
	} else {

		print GREEN,"Info: Data directory is $MYDATADIR\n",RESET if ($verbose);
	}

	@LISTALLDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null`;
	$compress = @LISTALLDYNAMIC;

	if ($compress < 2) {
		print RED, "Error: Dynamic Files cannot be found or are not compressed!\n", RESET;
		usage;
		exit 6;
	} else {
		print GREEN,"Info: Found $compress dynamic files under $MYDATADIR\n",RESET if ($verbose);
	}

	$FIRSTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | head -1 2>/dev/null`; chomp($FIRSTDYNAMIC);

	if ( ! -f $FIRSTDYNAMIC) {
		print RED, "Error: Could not find first dynamic file on $MYDATADIR data directory!\n", RESET;
		usage;
		exit 3;
	} else {
		print GREEN,"Info: The first dynamic file found is $FIRSTDYNAMIC\n",RESET if ($verbose);
	}

	$LASTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | tail -2 | head -1`; chomp($LASTDYNAMIC);

	if ( ! -f $LASTDYNAMIC) { 
		print RED, "Error: Could not find last dynamic file on $MYDATADIR data directory!\n", RESET;
		usage;
		exit 3;
	} else {
		print GREEN,"Info: The last dynamic file found is $LASTDYNAMIC\n",RESET if ($verbose);
	}

	if ($FIRSTDYNAMIC eq $LASTDYNAMIC) {
		print RED, "Error: Not enough dynamic files on $MYDATADIR data directory!\n", RESET;
		exit 3;
	}
}

sub gettingbasicinfo {

	# getting basic info from the host: hostname
	$hostnam = `grep hostname $STATIC | awk '{print \$3}' | head -1`; chomp ($hostnam);

	# finding rhel release
	my $rhelrelease = `grep ^"Red Hat Enterprise" $STATIC | head -1`;

	if ($rhelrelease =~ /^Red\sHat.*\srelease\s(\d)\.(\d)\s+\(.*/) {
		$rhel = $1;
		$rhelminor = $2;
		$rhelcomplete = "$rhel.$rhelminor";
	}

	# date of collection
	my $tempdate = `grep CitiHPC  $STATIC | tail -1`; chomp ($tempdate);
	$dateofdata = "$1/$2/$3" if ($tempdate =~ /on\s(\d\d)(\d\d)(\d\d)\sat/);

	print GREEN, "Info: Collector data from $dateofdata for hostname $hostnam RHEL $rhelcomplete\n", RESET;

}

sub reading_config {
	$simple = XML::Simple->new(); 
	$config_file = $simple->XMLin('./citihpc-analysis.xml'); 
#	print Dumper($config_file);
}

sub parsing_static {

	my @tempactivenics; my $tempcpucores; my $tempcpusiblings; my @tempmemsize; my @tempmemspeed;
	my @tempbroadcom; my @tempkernelvalue; my $counter; my $kernelparam; my $asuparam;
	my %nicringbuffers; my $nicring; 
	my $maximum = 0; my $key;
	my $arraycounter;

	my $tcpsegmentationoff = 0;
	my $genericsegmentationoff = 0;

	# will parse the static file and fill a bunch of temp variables for later conditions
	print BLUE, "Debug: Starting to parse static data\n", RESET if ($verbose);
	@staticfile = `cat $STATIC`;
	foreach (@staticfile) {
		#detecting the number of CPUs
		$numcores = ($1+1) if (/^processor\s+:\s(\d+)/); 

		# detecting active NICs - from ip addr command - filling a temp array
		#push (@tempactivenics, $1) if (/^\s+inet.*global\s(eth\d(\.\d+)?|bond\d)/);

		$test_nic{$1} = 1 if (/^\s+inet.*global\s(eth\d)(\.\d+)?/);

		# bond
		$test_nic{$1} = 1 if (/.*(eth\d)(\.\d+)?(\@\w+\d+)?:.*SLAVE.*mtu\s(\d+).*\smaster\s(bond\d)/);

		# finding out if hyperthreading is on, cpu cores and simblings must match
		$tempcpucores = $1 if (/^cpu\scores\s+:\s+(\d+)/);
		$tempcpusiblings = $1 if (/^siblings\s+:\s+(\d+)/);

		# finding logical volume
		$lvm = 1 if (/Logical\s[vV]olume/);	

		$IBM = 1 if (/Vendor:\sIBM/);

		$HP = 1 if (/Vendor:\sHP/);

		push (@tempmemsize, $1) if (/^\s+Size:\s(\d+)\sMB/);
		push (@tempmemspeed, $1) if (/^\s+Speed:\s(\d+)\sMHz/);

		push (@tempbroadcom, $1) if (/(eth\d):.*Broadcom/);


		# building a hash for kernel paramters
		if (/^(kernel|vm|fs|dev|net|abi|crypto|sunrpc\.)(.*)\s=\s(.*)\n/) {
			# sometimes the kernel value can be multiple numbers or words
			@tempkernelvalue = split (/\s+/, $3);
			$kernelparam = "$1"."$2";
			# if the values are indeed an array, treat as such
				$counter = 0;
				foreach (@tempkernelvalue) {
					$actualkernelparam{$kernelparam}[$counter] = "$_";
					$counter++;
				}

		}

		# IBM ASU paramters (when present)

		if (/^(IMM|SYSTEM_PROD_DATA|BootOrder|iSCSI|PXE|uEFI\.)(.*)=(.*)\n/) {
			# sometimes the kernel value can be multiple numbers or words
			$asuparam = "$1"."$2";
			$actualasuparam{$asuparam} = $3;

		}

		# building a hash for nic ring buffers - the output is tricky because the "Pre-set" and "Current" have the same format
		$nicring = $1 if (/^Ring\sparameters\sfor\s(eth\d):/);
		$maximum = 1 if (/^Pre-set\smaximums:/);
		$maximum = 0 if (/^Current\shardware\ssettings:/);
		if ($maximum) {
			$nicringbuffers{$nicring}{rxmax} = $1 if (/^RX:\s+(\d+)\n/);
			$nicringbuffers{$nicring}{txmax} = $1 if (/^TX:\s+(\d+)\n/);

		} else {
			$nicringbuffers{$nicring}{rxcurrent} = $1 if (/^RX:\s+(\d+)\n/);
			$nicringbuffers{$nicring}{txcurrent} = $1 if (/^TX:\s+(\d+)\n/);

		}
		
		$tcpsegmentationoff = 1 if (/^tcp-segmentation-offload:\s+off/);
		$genericsegmentationoff = 1 if (/^generic-segmentation-offload:\s+off/);
	}

	#print Dumper (\%actualkernelparam);
#	print Dumper (\%nicringbuffers);

	# hyperthread check
	if ( $tempcpucores eq $tempcpusiblings )  {
		$hypert = "(Hyperthreading is OFF)"; # this if for the graph title
		$ht="off";
	} else {
		$hypert = "(Hyperthreading is ON)"; # this is for the cpu graph title
		$ht="on";
	}

	if ($verbose) {
		print BLUE, "Debug: Checking for presence of Hyper-Threading\n", RESET;
		print BLUE, "Debug: hyper-threading should be set to $config_file->{hyperthread} , according to the config file\n", RESET;
		print BLUE, "Debug: Currently, hyper-threading is $ht on system because server has $tempcpucores cores and $tempcpusiblings siblings\n", RESET;
	}

	if ($config_file->{hyperthread} ne $ht) {
		if ($config_file->{hyperthread} eq "off") {
			push (@term_collector, "Hyper-threading (HT)is enabled. HT is not recommended for low latency due to jitter");
		} else {
			push (@term_collector, "Hyper-threading (HT)is not enabled. HT is recommended for grid compute nodes to optimize the use of cores.");
		}
	}

	print BLUE, "Debug: Checking for presence of Logical Volume\n", RESET if ($verbose);
	if (! $lvm) {
		push (@term_collector, "Logical Volume Manager is not in use. This can indicate that the system is not running the LLP or SOE Build.");
	}
	
	print BLUE, "Debug: Checking uniformity of speed and size of memory\n", RESET if ($verbose);
	my @uniqarray;

	@uniqarray = uniq ( @tempmemsize );
	$arraycounter = @uniqarray;
	if ($arraycounter > 1) {
		print RED, "Warning: Memory Size Not Uniform!\n", RESET if ($verbose);
		push (@term_collector, "Non uniform memory size has been detected which may lead to unpredictable speed and memory access.");
	} else {
		print BLUE, "Debug: Memory Size is uniform in $tempmemsize[0] Mb\n", RESET if ($verbose);
	}

	@uniqarray = uniq ( @tempmemspeed );
	$arraycounter = @uniqarray;
	if ($arraycounter > 1) {
		print RED, "Warning: Memory Speed Not Uniform across memory devices!\n", RESET if ($verbose);
		push (@term_collector, "Memory Speed is not uniform across the memory devices which may result in performance degradation.");
	} else {
		print BLUE, "Debug: Memory Speed is uniform in $tempmemspeed[0] MHz\n", RESET if ($verbose);
	}
	

	@activenics = keys (%test_nic); 
	$total_nics = @activenics;
	#print Dumper(\@activenics);
	#
	#
	# Checking if any of the active internface is a broadcom
	foreach (@tempbroadcom) {
		if (exists $test_nic{$_}) {
			print RED, "Warning: Broadcom NIC detected for interface $_. Not a Recommended Vendor\n", RESET if ($verbose);
			push (@term_collector, "Broadcom NIC has been detected in use on the system for interface $_. Not a favoured vendor!");
		}
	}

	# Checking ring buffers
	print BLUE, "Debug: Checking Ring Buffer Sizes...\n", RESET if ($verbose); 
	foreach $key (sort keys (%nicringbuffers)) {
		if ($nicringbuffers{$key}{rxmax} ne $nicringbuffers{$key}{rxcurrent}) {
			print RED, "Warning: Check RX Ring Buffer settings for interface $key. Current Settings: $nicringbuffers{$key}{rxcurrent}. Maximum Settings: $nicringbuffers{$key}{rxmax}\n", RESET if ($verbose);
			push (@term_collector, "The receive ring buffer is not set to the maximum. This can lead to packet drops!");
		}
		if ($nicringbuffers{$key}{txmax} ne $nicringbuffers{$key}{txcurrent}) {
			print RED, "Warning: Check TX Ring Buffer settings for interface $key. Current Settings: $nicringbuffers{$key}{txcurrent}. Maximum Settings: $nicringbuffers{$key}{txmax}\n", RESET if ($verbose);
			push (@term_collector, "The transmit ring buffer is not set to the maximum. This can lead to packet drops!");
		}

	}

	if ($tcpsegmentationoff) {
		print RED, "Warning: TCP Segmentation Offload is Off.\n", RESET if ($verbose);
		push (@term_collector, "TCP Segmentation Offload is disabled which can lead to higher CPU utilization.");
	}

	if ($genericsegmentationoff) {
		print RED, "Warning: Generic Segmentation Offload is Off.\n", RESET if ($verbose);
		push (@term_collector, "Generic Segmentation Offload is disabled which can lead to higher CPU utilization.");
	}

	&checking_kernel;
	
	#
#	#detecting the list of disks - they must be have "*vg-*" on it - this data is only on dynamic
	my @temp_list_disks = `zcat $LASTDYNAMIC`; my %temp_disk;
	for (@temp_list_disks) {
		if (/^Average:\s+(\w+vg-\w+|dev\d+-\d+|cciss\/\w+|sticore-\w+)\s+\d+\.*/){
			$temp_disk{$1} = 1;
		}
	}
	@list_disks = sort keys (%temp_disk); $total_disks = @list_disks;

}

sub checking_kernel {
	my $key, my $arraysize; my $counter;
	my $notmatch = 0;
	my $globalnotmatch = 0;
	print BLUE, "Debug:  Checking for sysctl (kernel) Parameters.\n", RESET if ($verbose);
	foreach $key (sort (keys %{$config_file->{kernel}{parameter}})) {
	#	print BLUE, "Debug: checking $key ... \n", RESET if ($verbose);
		if (exists $actualkernelparam{$key}) {
			# check if the paramer is multi value
			if (ref $config_file->{kernel}{parameter}{$key}{value} eq 'ARRAY') {
				#print BLUE, "Debug: $key has multi values : @{$config_file->{kernel}{parameter}{$key}{value}} \n", RESET if ($verbose);
				$arraysize = @{$config_file->{kernel}{parameter}{$key}{value}};
				for ($counter = 0; $counter < $arraysize; $counter++) {
					if ($config_file->{kernel}{parameter}{$key}{value}[$counter] ne $actualkernelparam{$key}[$counter]) {
						$notmatch = 1;
						$globalnotmatch = 1;
					}
				}
				if ($notmatch) {
					print RED, "Warning: Parameter mismatch for $key. Value detected: @{$actualkernelparam{$key}}. Actual Value Expected @{$config_file->{kernel}{parameter}{$key}{value}}\n", RESET if ($verbose);
				}
			} else {
				# it is a single value parameter
	#			print BLUE, "Debug: $key has reference value of $config_file->{kernel}{parameter}{$key}{value} \n", RESET if ($verbose);
				if ($config_file->{kernel}{parameter}{$key}{value} ne $actualkernelparam{$key}[0]) {
					print RED, "Warning: Parameter mismatch for $key. Value detected: $actualkernelparam{$key}[0]. Actual Value Expected:  $config_file->{kernel}{parameter}{$key}{value}\n", RESET if ($verbose);
					$globalnotmatch = 1;
				}
			}
		} else {
			print RED, "Warning: kernel parameter $key does not exist on the system. Check forensics config file or the RHEL release for the parameter!\n", RESET;
		}
		$notmatch = 0;
	}
	if ($globalnotmatch) {
		 push (@term_collector, "Kernel Parameters are not finely tuned for low latency or intense compute application!");

	}
}

sub checking_asu {
	print BLUE, "Debug: Checking for asu (IBM BIOS) parameters if exists.\n", RESET if ($verbose);
	my $arraysize; my @asuparameters; my $globalnotmatch = 0; my $found_asu_parameters; my $key;
	$found_asu_parameters = keys(%actualasuparam);
	if ($found_asu_parameters < 4) {
		print RED, "Warning: No ASU parameters found on static file.\n", RESET if ($verbose);
		return 2;
	}
	
	foreach $key (sort (keys %{$config_file->{ibmbios}{parameter}})) {
	#	print BLUE, "Debug: checking $key ... \n", RESET if ($verbose);
		if (exists $actualasuparam{$key}) {
#			print BLUE, "Debug: $key has reference value of $config_file->{kernel}{parameter}{$key}{value} \n", RESET if ($verbose);
			if ($config_file->{ibmbios}{parameter}{$key}{value} ne $actualasuparam{$key}) {
				print RED, "Warning: Parameter mismatch for $key. Value detected: $actualasuparam{$key}. Actual Value Expected:  $config_file->{ibmbios}{parameter}{$key}{value}\n", RESET if ($verbose);
				$globalnotmatch = 1;
			}
		} else {
			print RED, "Warning: asu parameter $key does not exist on the system. Check forensics config file or the IBM BIOS release for the parameter!\n", RESET;
		}
	}
	if ($globalnotmatch) {
		push (@term_collector, "BIOS settings are not optimized for low latency or intense compute application!");
	}

}

sub checking_conrep {
	$CONREP=`ls ${MYDATADIR}/conrep* 2>/dev/null | head -1 2>/dev/null`; chomp($CONREP);
	if ( -f $CONREP) {
		$conrep_simple = XML::Simple->new(); 
		$conrep_config = $conrep_simple->XMLin($CONREP);
#		print Dumper ($conrep_config); 
		my $key;
		my $notmatch = 0;
		my $globalnotmatch = 0;
		print BLUE, "Debug: Checking for conrep Parameters.\n", RESET if ($verbose);
		foreach $key (sort (keys %{$config_file->{hpbios}{parameter}})) {
			print BLUE, "Debug: checking $key ... \n", RESET if ($verbose);
			if (exists $conrep_config->{Section}{$key}) {
				if ($config_file->{hpbios}{parameter}{$key}{value} ne $conrep_config->{Section}{$key}{content}) {
						print RED, "Warning: Conrep parameter mismatch for $key. Value detected: $conrep_config->{Section}{$key}{content}. Actual Value Expected: $config_file->{hpbios}{parameter}{$key}{value}\n", RESET if ($verbose);
						$globalnotmatch = 1;
				}
			} else {
				print RED, "Warning: conrep parameter $key does not exist on the system. Check forensics config file or the Conrep release for the parameter!\n", RESET;
			}
		}
		if ($globalnotmatch) {
			push (@term_collector, "BIOS settings are not optimized for low latency or intense compute application!");
		}
	} else {
               print RED, "Warning: Could not find conrep file on $MYDATADIR data directory!\n", RESET if ($verbose);
	}

}

sub compare_first_last_dynamic {

	print BLUE, "Debug: Starting to parse dynamic data - network metrics\n", RESET if ($verbose);
	my $key; my $nic; my $nicmetric; my $diff;
	%first_dynamic = load_dynamic_data($FIRSTDYNAMIC);
	#print Dumper (\%first_dynamic);
	%last_dynamic = load_dynamic_data($LASTDYNAMIC);
	#print Dumper (\%last_dynamic);
	#
	foreach $key (sort (keys(%last_dynamic))) {

		if ($key eq "interface") {
			foreach $nic (sort (keys(%{$last_dynamic{interface}}))) {
				foreach $nicmetric (sort (keys(%{$last_dynamic{interface}{$nic}}))) {
					$diff = $last_dynamic{interface}{$nic}{$nicmetric} - $first_dynamic{interface}{$nic}{$nicmetric};
					if ($diff > 0) {
						print RED, "Warning: $nic parameter $nicmetric detected with a difference of $diff\n", RESET if ($verbose);
						push (@term_collector, "NIC $nic metrics which may indicate network degradation.");
					}
				}
			} 
			next;
		}

		# netstat parameters
		#
		$diff = $last_dynamic{$key} - $first_dynamic{$key};
		if ($diff > 0) {
			print RED, "Warning: $key parameter detected with a difference of $diff\n", RESET if ($verbose);
			push (@term_collector, "$key has been detected which may indicate network degradation.");
		}

	}	
}

sub load_dynamic_data(\%$)  {

	my %dynamic_data;
	#%dynamic_data = %{$_[0]};
	#my $file = $_[1];
	my $file = $_[0];
        my @fileline = `zcat $file`;
	my $nicifconfig; $nicifconfig = "dummy"; 
	my $nicethtool;
	$nicethtool = "dummy";
        foreach (@fileline) {
		$dynamic_data{"TCP Segments Retransmited"} = $1 if (/\s+(\d+)\s+segments\sretransmited\n/);	
		$dynamic_data{"UDP Buffer Overflows"} = $1 if (/\s+(\d+)\s+packet\sreceive\serrors\n/);	
		$dynamic_data{"TCP data loss"} = $1 if (/\s+(\d+)\s+TCP\sdata\sloss\sevents\n/);	
		$dynamic_data{"Socket Buffer Overruns"} = $1 if (/\s+(\d+)\s+packets\spruned\sfrom\sreceive\squeue\sbecause\sof\ssocket\sbuffer\soverrun\n/);
		$dynamic_data{"TCP Timeouts"} = $1 if (/\s+(\d+)\s+other\sTCP\stimeouts\n/);
		$dynamic_data{"Connections Aborted Due to Timeout"} = $1 if (/\s+(\d+)\s+connections\saborted\sdue\s\to\stimeout\n/);
		$dynamic_data{"TCP Packets Collapsed"} = $1 if (/\s+(\d+)\s+packets\scollapsed.*\n/);
		$dynamic_data{"TCP Packets Rejected"} = $1 if (/\s+(\d+)\s+packets\srejects.*\n/);
		$dynamic_data{"IP Outgoing Packets Dropped"} = $1 if (/\s+(\d+)\s+outgoing\spackets\sdropped\n/);
		$dynamic_data{"ICMP Message Failure"} = $1 if (/\s+(\d+)\s+.*ICMP\smessage\sfailed\n/);

		if (/^(eth\d|bond\d)\s+Link\sencap:Ethernet/) {
			$nicifconfig = $1;
			next;
		}
		if (/\s+(RX|TX)\s+packets:\d+\s+errors:(\d+)\s+dropped:(\d+)\s+overruns:(\d+)\s+(frame|carrier):(\d+)/) {
			$dynamic_data{interface}{$nicifconfig}{"$1 errors"} = $2;
			$dynamic_data{interface}{$nicifconfig}{"$1 dropped"} = $3;
			$dynamic_data{interface}{$nicifconfig}{"$1 overruns"} = $4;
			$dynamic_data{interface}{$nicifconfig}{"$1 $5"} = $6;
		}
		if (/^(eth\d)\s-\sNIC\sStatistics/) {
			$nicethtool = $1 ;
			next;
		}
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(tx_error_bytes):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*errors.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*collisions.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*deferred.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*fragments.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*jabbers.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*undersize.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*too_small.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*too_short.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*too_long.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*too_many.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*oversize.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*overflow.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*discards.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*fail.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*drop.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*stops.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(be_on_die.*):\s+(\d+)\n/);
		$dynamic_data{interface}{$nicethtool}{$1} = $2 if (/\s+(.*errs.*):\s+(\d+)\n/);
	}
	#print Dumper (\%dynamic_data);
	return %dynamic_data;
}


sub parsing_all_dynamic {

	print BLUE, "Debug: Starting to parse all dynamic data \n", RESET if ($verbose);
	$graphdat = "$config_file->{heatmapfilename}$hostnam-cpu.dat"; 
	$graphdatmem = "$config_file->{heatmapfilename}$hostnam-mem.dat"; 
	$graphdatnic = "$config_file->{heatmapfilename}$hostnam-nic.dat"; 
	$graphdatdiskawait = "$config_file->{heatmapfilename}$hostnam-disk.await.dat"; 
	$graphdatdiskcpu = "$config_file->{heatmapfilename}$hostnam-disk.cpu.dat"; 
	$graphdatdiskread = "$config_file->{heatmapfilename}$hostnam-disk.read.dat"; 
	$graphdatdiskwrite = "$config_file->{heatmapfilename}$hostnam-disk.write.dat"; 
	
	my $cpucounter = 0;
	my $diskcounter = 0;
	my $highcpudiskcounter = 0;
	my $swapcounter = 0;
	my $contextcounter = 0;
 
	open (my $fh, '>', $graphdat) or die "Could not open file '$graphdat' $!";
	open (my $fhmem, '>', $graphdatmem) or die "Could not open file '$graphdatmem' $!";
	open (my $fhnic, '>', $graphdatnic) or die "Could not open file '$graphdatnic' $!";
	open (my $fhdiska, '>', $graphdatdiskawait) or die "Could not open file '$graphdatdiskawait' $!";
	open (my $fhdiskcpu, '>', $graphdatdiskcpu) or die "Could not open file '$graphdatdiskcpu' $!";
	open (my $fhdiskread, '>', $graphdatdiskread) or die "Could not open file '$graphdatdiskread' $!";
	open (my $fhdiskwrite, '>', $graphdatdiskwrite) or die "Could not open file '$graphdatdiskwrite' $!";
	foreach (@LISTALLDYNAMIC) {
		chomp;
		open ("logfile", sprintf("zcat %s |", $_)) || die "can't open pipe from command 'zcat  $_' : $!\n";
		my @datarray; my @datarraymem; my @datarraynic; my @datarraydiska; my @datarraydiskcpu; my @datarraydiskread; my @datarraydiskwrite;
		my %temp_nic; my %temp_disk;
		my $entry = 0;
		my $entrynic = 0; my %counter; 

		# setting the counters for each disk (iostat has two sections, i do not care for the 1st section
		for (@list_disks) {
			$counter{$_} = 2;
		}
		
		while (<logfile>) {	
			if (/^Info: sar.*(\d\d\:\d\d\:\d\d).*/){
				push (@datarray, $1);
				push (@datarraynic, $1);
				push (@datarraydiska, $1);
				push (@datarraydiskcpu, $1);
				push (@datarraydiskread, $1);
				push (@datarraydiskwrite, $1);
				next;
			}
			if ($rhel eq "5")  {
				if (/^Average:\s+(all|\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)/){
					# on RHEL5 there is fewer columns $7 is CPU idle
					# and it is more difficult to parse data becuase there is "garbage" from interruptions  - hence the counter hack
					$entry++;
					if ($entry <= ($numcores+2)) {
						push (@datarray, sprintf("%.2f",100-$7));
						# setup a counter for CPU high utilization
						if ($7 <= $config_file->{cpuwarning}) {
							$cpucounter++;
						}
					}

					next;
				}
			} else {
				if (/^Average:\s+(all|\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)/){
					# $10 is CPU idle - grpah is utilization, hence a little subtraction from "100"
					push (@datarray, sprintf("%.2f",100-$10));
					# setup a counter for CPU high utilization
					if ($10 <= $config_file->{cpuwarning}) {
						$cpucounter++;
					}
					next;
				}


			}
			if (/^Info: free.*(\d\d\:\d\d\:\d\d).*/){
				push (@datarraymem, $1);
				next;
			}
			if (/^Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/){
				# $1 is total
				# $2 is used
				# $3 is free
				# $4 is shared
				# $5 is buffers - according to RedHat it is useless
				# $6 is cached
				#
				#Number in Mb
				#
				push (@datarraymem,  sprintf("%.2f", $1/1024/1024));
				push (@datarraymem,  sprintf("%.2f", $2/1024/1024));
				push (@datarraymem,  sprintf("%.2f", $6/1024/1024));
				push (@datarraymem,  sprintf("%.2f", $4/1024/1024));
			}
			if (/^Swap:\s+\d+\s+(\d+)\s+\d+\n/){
				if ($1 > 0) {
					$swapcounter++;
					push (@datarraymem,  sprintf("%.2f", $1/1024/1024));
				} else {
					push (@datarraymem,  sprintf("%.2f", $1));
				}
			}
			# NIC data
			if (/^Average:\s+(eth\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)/){
			# IFACE   rxpck/s   txpck/s   rxbyt/s   txbyt/s   rxcmp/s   txcmp/s  rxmcst/s
			# $1 is NIC
			# $4 is RX in bytes
			# $5 is TX in bytes 
			#
				# the nic must be active to be in graph, otherwise, skip
				if (exists $test_nic{$1}) {
					$entrynic++;
					if ($entrynic <= $total_nics) {
						if ($4 eq 0) {
							$temp_nic{$1}{rx} = $4;
						} else {
							$temp_nic{$1}{rx} = sprintf("%.2f",$4/1024);
						}
						if ($5 eq 0) {
							$temp_nic{$1}{tx} = $5;
						} else {
							$temp_nic{$1}{tx} = sprintf("%.2f",$5/1024);
						}
					}
				}
			}


			# disk data
			if (/^Average:\s+(\w+vg-\w+|dev\d+-\d+|cciss\/\w+|sticore-\w+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)/){
				#$counter{$1}++;
				#next if ($counter{$1}%2==1);
				# $1 is the disk (it must have "vg" on it
				# $3 is read sector per sec - sector size is 512 bytes. Dividind this number by 2 gives in Kb. Div by 2048 in Mb.
				# $4 is write sector per sec - see above.
				# $7 is await time (average per operation)
				# $9 is CPU
				$temp_disk{$1}{await} = $7;
				$temp_disk{$1}{cpu} = $9;
				$temp_disk{$1}{read} = $3/2048;
				$temp_disk{$1}{write} = $4/2048;

				if ($7 > $config_file->{disklatencywarning}) {
					$diskcounter++;
				}
				if ($9 > $config_file->{highcpudiskwarning}) {
					$highcpudiskcounter++;
				}
			}

			# counter for context switing
			if (/^Average:\s+\d+\.\d+\s+([1-9]\d+\.\d+)\n/) {
				if ($1 > $config_file->{contextswitchwarning}) {
					$contextcounter++;
				}
			}
				
		}

#		print Dumper(\%temp_nic);
		#print Dumper(\%temp_disk);
#
#		printing data on files
		print $fh join("\t" , @datarray),"\n";
		print $fhmem join("\t" , @datarraymem),"\n";
		# nic data requires a little treatment to enforce sequence
		for (@activenics) {
			push (@datarraynic, $temp_nic{$_}{rx});
			push (@datarraynic, $temp_nic{$_}{tx});
		}
		print $fhnic join("\t" , @datarraynic),"\n";
		# disk stuff
		for (@list_disks) {
			push (@datarraydiska,  $temp_disk{$_}{await});
			push (@datarraydiskcpu,  $temp_disk{$_}{cpu});
			push (@datarraydiskread,  $temp_disk{$_}{read});
			push (@datarraydiskwrite,  $temp_disk{$_}{write});
		}
		print $fhdiska join("\t" , @datarraydiska),"\n";
		print $fhdiskcpu join("\t" , @datarraydiskcpu),"\n";
		print $fhdiskread join("\t" , @datarraydiskread),"\n";
		print $fhdiskwrite join("\t" , @datarraydiskwrite),"\n";
		close ("logfile");
	}
	close $fh;
	close $fhmem;
	close $fhnic;
	close $fhdiska;
	close $fhdiskcpu;
	close $fhdiskread;
	close $fhdiskwrite;

	if ($cpucounter > 0) {
		print RED, "Warning: CPU idleness less than the threshold of $config_file->{cpuwarning} % for $cpucounter times\n", RESET if ($verbose);
		push (@term_collector, "High CPU Utilization detected.");

	}
	if ($diskcounter > 0) {
		print RED, "Warning: Disk latency more than the threshold of $config_file->{disklatencywarning} milliseconds for $diskcounter times\n", RESET if ($verbose);
		push (@term_collector, "Excessive disk latency detected.");

	}
	if ($highcpudiskcounter > 0) {
		print RED, "Warning: High CPU utilization detected to perform IO operations, above the threshold of $config_file->{highcpudiskwarning} % for $highcpudiskcounter times\n", RESET if ($verbose);
		push (@term_collector, "Excessive CPU for disk operations detected.");

	}
	if ($swapcounter > 0) {
		print RED, "Warning: Memory Swapping on the system!\n", RESET if ($verbose);
		push (@term_collector, "Memory Swapping has been detected which could cause severe performance degradation!");

	}
	if ($contextcounter > 0) {
		print RED, "Warning: Context Switching more than the threshold of $config_file->{contextswitchwarning} context switches/sec for $contextcounter times\n", RESET if ($verbose);
		push (@term_collector, "High Context Switching detected.");

	}

}

# the following return an uniq elements of the array
sub uniq {
  my %seen;
  return grep { !$seen{$_}++ } @_;
}

sub printing_analysismessages {

	print BLUE, "Debug: Printing findings\n", RESET if ($verbose);
	print RED, "Warning: Following Sub Optimal Configurations have been detected in the system:\n", RESET;
	foreach (@term_collector) {
		print RED "$_\n", RESET;
	}
	print RED, "Please contact SA for help! For technical details, execute the script in verbose [-v] more. Thank you.\n", RESET;
	print GREEN, "Info: End of analysis.\n", RESET;

}


sub creating_line_graph {


	# finding the number of CPUs from the dat file (from the number of columns minus 2)
	my $numcpu = `cat $graphdat | awk '{print NF}' | head -1`; chomp ($numcpu);
	$numcpu = $numcpu - 1;

	my $data = GD::Graph::Data->new();
	$data->read(file=> $graphdat);

	my $mylinegraph = GD::Graph::mixed->new($horizontalsize, $verticalsize) or die "Can't create graph!";

	$mylinegraph->set(
	      title             => "Total (bar) and Individual (line) CPU %utilization - server $hostnam $hypert - $dateofdata",
		types		=> [@mytypecpu],
		dclrs		=> [@mycolors],
		transparent	=> 0,
		# top margin
		t_margin	=> 50,
		# bottom margin
		b_margin	=> 5,
		# space between text and graph, default 8
		text_space	=> 16,
	);

	# the following is not working , need to check why
	#$mylinegraph->set_title_font('arial', 12);
	$mylinegraph->set_title_font(gdLargeFont);

	$mylinegraph->set( 
	      x_label           => 'Time',
	      x_label_skip      => 8, 
	      x_labels_vertical      => 1, 
	      y_label           => 'CPU %',
	      y_max_value       => 100,
	      y_min_value       => 0,
	      y_tick_number     => 10,
	      y_label_skip      => 0,
		# no border - difficult to read when CPUs are 100% all the timesS
		box_axis	=> 0,
	
	  ) or die $mylinegraph->error;

	$mylinegraph->set_legend_font(gdLargeFont);
	$mylinegraph->set_legend(@mycpulegend);

	my $linegraph = $mylinegraph->plot($data) or die $mylinegraph->error;

	if ( -f $config_file->{graphlogo} ) {
		# adding the logo
		my $logo = GD::Image->newFromPng($config_file->{graphlogo});
		my ($w, $h) = $logo->getBounds( );
		$linegraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);
	}

	my $pnglinefile="$config_file->{heatmapfilename}$hostnam-cpu.png";
	open(IMG, ">$pnglinefile") or die $!;
	binmode IMG;
	print IMG $linegraph->png;

}

sub creating_mem_graph {

	my $datamem = GD::Graph::Data->new();
	$datamem->read(file=> $graphdatmem);

	my $mymemgraph = GD::Graph::mixed->new($horizontalsize, $verticalsize) or die "Can't create graph!";

	$mymemgraph->set(
	      title             => "Memory Utilization - server $hostnam  - $dateofdata",
		types		=>  [qw(area area area area area)],
		dclrs		=>  [qw(green red blue gray yellow)],
		transparent	=> 0,
		# top margin
		t_margin	=> 50,
		# bottom margin
		b_margin	=> 5,
		# space between text and graph, default 8
		text_space	=> 16,
	);

	# the following is not working , need to check why
	#$mylinegraph->set_title_font('arial', 12);
	$mymemgraph->set_title_font(gdLargeFont);

	$mymemgraph->set( 
	      x_label           => 'Time',
	      x_label_skip      => 8, 
	      x_labels_vertical      => 1, 
	      y_label           => 'GB',
	      y_max_value       => ($datamem->get_min_max_y_all( ))[1]+2,
	      y_min_value       => 0,
	      y_tick_number     => 10,
	      y_label_skip      => 0,
		y_number_format   => sub { int(shift); }, 
	  ) or die $mymemgraph->error;

	$mymemgraph->set_legend_font(gdLargeFont);
	$mymemgraph->set_legend(qw (FREE USED BUFFERS SHARED SWAP));

	my $memgraph = $mymemgraph->plot($datamem) or die $mymemgraph->error;

	if ( -f $config_file->{graphlogo} ) {
		# adding the logo
		my $logo = GD::Image->newFromPng($config_file->{graphlogo});
		my ($w, $h) = $logo->getBounds( );
		$memgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);
	}
	my $pngmemfile="$config_file->{heatmapfilename}$hostnam-mem.png";
	open(IMG, ">$pngmemfile") or die $!;
	binmode IMG;
	print IMG $memgraph->png;
}


sub creating_nic_graph {

	# setting up pre-defined arrays - up to 60 elements
	my $datanic = GD::Graph::Data->new();
	$datanic->read(file=> $graphdatnic);

	my $mynicgraph = GD::Graph::lines->new($horizontalsize, $verticalsize) or die "Can't create graph!";

	my @listofcolors = splice @mycolors, 0 , $total_nics*2;
	$mynicgraph->set(
	      title             => "NIC utilization in Kbytes/s - server $hostnam $nicextralegend  - $dateofdata",
		dclrs		=> [@listofcolors],
		transparent	=> 0,
		# top margin
		t_margin	=> 50,
		# bottom margin
		b_margin	=> 5,
		# space between text and graph, default 8
		text_space	=> 16,
	);

	# the following is not working , need to check why
	#$mylinegraph->set_title_font('arial', 12);
	$mynicgraph->set_title_font(gdLargeFont);

	$mynicgraph->set( 
	      x_label           => 'Time',
	      x_label_skip      => 8, 
	      x_labels_vertical      => 1, 
	      y_label           => 'Kbytes/s',
	      y_max_value       => ($datanic->get_min_max_y_all( ))[1]+2,
	      y_min_value       => 0,
	      y_tick_number     => 10,
	      y_label_skip      => 0, 
	  ) or die $mynicgraph->error;

	# setting up the legend - need to detect the right NICs to display on legend
	my @nic_legend;
	for (@activenics) {
		my $tempnicuc = uc($_);
		push (@nic_legend, "$tempnicuc RX");
		push (@nic_legend, "$tempnicuc TX");
	}
	
	$mynicgraph->set_legend_font(gdLargeFont);
	$mynicgraph->set_legend(@nic_legend);

	my $nicgraph = $mynicgraph->plot($datanic) or die $mynicgraph->error;

	if ( -f $config_file->{graphlogo} ) {
		# adding the logo
		my $logo = GD::Image->newFromPng($config_file->{graphlogo});
		my ($w, $h) = $logo->getBounds( );
		$nicgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);
	}

	my $pngnicfile="$config_file->{heatmapfilename}$hostnam-nic.png";
	open(IMG, ">$pngnicfile") or die $!;
	binmode IMG;
	print IMG $nicgraph->png;

}

sub creating_diskawait_graph {

	my $datadiska = GD::Graph::Data->new();
	#$datamem->read(file=> $graphdatmem);
	$datadiska->read(file=> $graphdatdiskawait);

	my $mydiskagraph = GD::Graph::mixed->new($horizontalsize, $verticalsizedisk) or die "Can't create graph!";

	$mydiskagraph->set(
	      title             => "Disk Latency in milliseconds - server $hostnam  - $dateofdata",
		types		=>  [@mytype],
		dclrs		=>  [@mycolors],
		transparent	=> 0,
		# top margin
		t_margin	=> 50,
		# bottom margin
		b_margin	=> 5,
		# space between text and graph, default 8
		text_space	=> 16,
	);

	# the following is not working , need to check why
	#$mylinegraph->set_title_font('arial', 12);
	$mydiskagraph->set_title_font(gdLargeFont);

	$mydiskagraph->set( 
	      x_label           => 'Time',
	      x_label_skip      => 8, 
	      x_labels_vertical      => 1, 
	      y_label           => 'milliseconds',
	      y_max_value       => ($datadiska->get_min_max_y_all( ))[1]+1,
	      y_min_value       => 0,
#	      y_tick_number     => ($datadiska->get_min_max_y_all( ))[1]+1,
	      y_label_skip      => 0,
		y_number_format   => sub { int(shift); }, 
	  ) or die $mydiskagraph->error;

        my @disk_legend;

        for (@list_disks) {
                my $tempdiskuc = uc($_);
                push (@disk_legend, $tempdiskuc);
        }
#        print Dumper(\@disk_legend);

	$mydiskagraph->set_legend_font(gdLargeFont);
        $mydiskagraph->set_legend(@disk_legend);

	my $diskagraph = $mydiskagraph->plot($datadiska) or die $mydiskagraph->error;

	if ( -f $config_file->{graphlogo} ) {
		# adding the logo
		my $logo = GD::Image->newFromPng($config_file->{graphlogo});
		my ($w, $h) = $logo->getBounds( );
		$diskagraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);
	}

	my $pngdiskafile="$config_file->{heatmapfilename}$hostnam-disk-latency.png";
	open(IMG, ">$pngdiskafile") or die $!;
	binmode IMG;
	print IMG $diskagraph->png;
}

sub creating_diskcpu_graph {

	my $datadiskc = GD::Graph::Data->new();
	$datadiskc->read(file=> $graphdatdiskcpu);

	my $mydiskcgraph = GD::Graph::mixed->new($horizontalsize, $verticalsizedisk) or die "Can't create graph!";

	$mydiskcgraph->set(
	      title             => "%CPU used for IO Operations - server $hostnam  - $dateofdata",
		types		=>  [@mytype],
		dclrs		=>  [@mycolors],
		transparent	=> 0,
		# top margin
		t_margin	=> 50,
		# bottom margin
		b_margin	=> 5,
		# space between text and graph, default 8
		text_space	=> 16,
	);

	# the following is not working , need to check why
	#$mylinegraph->set_title_font('arial', 12);
	$mydiskcgraph->set_title_font(gdLargeFont);

	$mydiskcgraph->set( 
	      x_label           => 'Time',
	      x_label_skip      => 8, 
	      x_labels_vertical      => 1, 
	      y_label           => 'CPU%',
	      y_max_value       => ($datadiskc->get_min_max_y_all( ))[1]+1,
	      y_min_value       => 0,
#	      y_tick_number     => ($datadiskc->get_min_max_y_all( ))[1]+1,
	      y_label_skip      => 0,
		y_number_format   => sub { int(shift); }, 
	  ) or die $mydiskcgraph->error;

        my @disk_legend;

        for (@list_disks) {
                my $tempdiskuc = uc($_);
                push (@disk_legend, $tempdiskuc);
        }
#        print Dumper(\@disk_legend);

	$mydiskcgraph->set_legend_font(gdLargeFont);
        $mydiskcgraph->set_legend(@disk_legend);

	my $diskcgraph = $mydiskcgraph->plot($datadiskc) or die $mydiskcgraph->error;

	if ( -f $config_file->{graphlogo} ) {
		# adding the logo
		my $logo = GD::Image->newFromPng($config_file->{graphlogo});
		my ($w, $h) = $logo->getBounds( );
		$diskcgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);
	}

	my $pngdiskcfile="$config_file->{heatmapfilename}$hostnam-disk-cpu.png";
	open(IMG, ">$pngdiskcfile") or die $!;
	binmode IMG;
	print IMG $diskcgraph->png;
}

sub creating_diskread_graph {

	my $datadiskr = GD::Graph::Data->new();
	$datadiskr->read(file=> $graphdatdiskread);

	my $mydiskrgraph = GD::Graph::mixed->new($horizontalsize, $verticalsizedisk) or die "Can't create graph!";

	$mydiskrgraph->set(
	      title             => "Disk Reads in Mbytes/sec - server $hostnam  - $dateofdata",
		types		=>  [@mytype],
		dclrs		=>  [@mycolors],
		transparent	=> 0,
		# top margin
		t_margin	=> 50,
		# bottom margin
		b_margin	=> 5,
		# space between text and graph, default 8
		text_space	=> 16,
	);

	# the following is not working , need to check why
	$mydiskrgraph->set_title_font(gdLargeFont);

	$mydiskrgraph->set( 
	      x_label           => 'Time',
	      x_label_skip      => 8, 
	      x_labels_vertical      => 1, 
	      y_label           => 'Mbytes/sec',
	      y_max_value       => ($datadiskr->get_min_max_y_all( ))[1]+1,
	      y_min_value       => 0,
#	      y_tick_number     => ($datadiskr->get_min_max_y_all( ))[1]+1,
	      y_label_skip      => 0,
		y_number_format   => sub { int(shift); }, 
	  ) or die $mydiskrgraph->error;

        my @disk_legend;

        for (@list_disks) {
                my $tempdiskuc = uc($_);
                push (@disk_legend, $tempdiskuc);
        }
#        print Dumper(\@disk_legend);

	$mydiskrgraph->set_legend_font(gdLargeFont);
        $mydiskrgraph->set_legend(@disk_legend);

	my $diskrgraph = $mydiskrgraph->plot($datadiskr) or die $mydiskrgraph->error;

	if ( -f $config_file->{graphlogo} ) {
		# adding the logo
		my $logo = GD::Image->newFromPng($config_file->{graphlogo});
		my ($w, $h) = $logo->getBounds( );
		$diskrgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);
	}

	my $pngdiskrfile="$config_file->{heatmapfilename}$hostnam-disk-read.png";
	open(IMG, ">$pngdiskrfile") or die $!;
	binmode IMG;
	print IMG $diskrgraph->png;
}

sub creating_diskwrite_graph {

	my $datadiskw = GD::Graph::Data->new();
	$datadiskw->read(file=> $graphdatdiskwrite);

	my $mydiskwgraph = GD::Graph::mixed->new($horizontalsize, $verticalsizedisk) or die "Can't create graph!";

	$mydiskwgraph->set(
	      title             => "Disk Writes in Mbytes/sec - server $hostnam  - $dateofdata",
		types		=>  [@mytype],
		dclrs		=>  [@mycolors],
		transparent	=> 0,
		# top margin
		t_margin	=> 50,
		# bottom margin
		b_margin	=> 5,
		# space between text and graph, default 8
		text_space	=> 16,
	);

	# the following is not working , need to check why
	$mydiskwgraph->set_title_font(gdLargeFont);

	$mydiskwgraph->set( 
	      x_label           => 'Time',
	      x_label_skip      => 8, 
	      x_labels_vertical      => 1, 
	      y_label           => 'Mbytes/sec',
	      y_max_value       => ($datadiskw->get_min_max_y_all( ))[1]+1,
	      y_min_value       => 0,
#	      y_tick_number     => ($datadiskw->get_min_max_y_all( ))[1]+1,
	      y_label_skip      => 0,
		y_number_format   => sub { int(shift); }, 
	  ) or die $mydiskwgraph->error;

        my @disk_legend;

        for (@list_disks) {
                my $tempdiskuc = uc($_);
                push (@disk_legend, $tempdiskuc);
        }
#        print Dumper(\@disk_legend);

	$mydiskwgraph->set_legend_font(gdLargeFont);
        $mydiskwgraph->set_legend(@disk_legend);

	my $diskwgraph = $mydiskwgraph->plot($datadiskw) or die $mydiskwgraph->error;

	if ( -f $config_file->{graphlogo} ) {
		# adding the logo
		my $logo = GD::Image->newFromPng($config_file->{graphlogo});
		my ($w, $h) = $logo->getBounds( );
		$diskwgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);
	}

	my $pngdiskwfile="$config_file->{heatmapfilename}$hostnam-disk-write.png";
	open(IMG, ">$pngdiskwfile") or die $!;
	binmode IMG;
	print IMG $diskwgraph->png;
}

sub preping_data_graphs {

        if ($compress < 1100) {
                $horizontalsize=1200;
                $verticalsize=600;
        } else {
                $horizontalsize=$compress+100;
                $verticalsize=600;
        }

        # disk requires a talled graph if there is so many of them
        if ($total_disks < 160) {
                $verticalsizedisk=600;
        } else {
                $verticalsizedisk=1500;
        }

	my $countertype = 0;
	while ($countertype < 800) {
		$mytype[$countertype] = "lines";
		$countertype++;
	}

	my $countertypecpu = 0;
	$mytypecpu[$countertypecpu] = "bars"; my $countertemp;
	$mycpulegend[$countertypecpu] = "ALL";
	while ($countertypecpu < 160) {
		$countertemp = $countertypecpu;
		$countertypecpu++;
		$mytypecpu[$countertypecpu] = "lines";
		$mycpulegend[$countertypecpu] = "CPU$countertemp";
	}

	my $countercolor = 0;
	$mycolors[$countercolor] = "marine";
	while ($countercolor < 900) {
		$countercolor++;
		$mycolors[$countercolor] = "red";
		$countercolor++;
		$mycolors[$countercolor] = "green";
		$countercolor++;
		$mycolors[$countercolor] = "blue";
		$countercolor++;
		$mycolors[$countercolor] = "gray";
		$countercolor++;
		$mycolors[$countercolor] = "yellow";
		$countercolor++;
		$mycolors[$countercolor] = "purple";
		$countercolor++;
		$mycolors[$countercolor] = "orange";
		$countercolor++;
		$mycolors[$countercolor] = "pink";
		$countercolor++;
		$mycolors[$countercolor] = "cyan";
		$countercolor++;
		$mycolors[$countercolor] = "dbrown";
		$countercolor++;
		$mycolors[$countercolor] = "dred";
		$countercolor++;
		$mycolors[$countercolor] = "dblue";
		$countercolor++;
		$mycolors[$countercolor] = "dgreen";
		$countercolor++;
		$mycolors[$countercolor] = "dgray";
		$countercolor++;
		$mycolors[$countercolor] = "dyellow";
		$countercolor++;
		$mycolors[$countercolor] = "dpurple";
		$countercolor++;
		$mycolors[$countercolor] = "dpink";
		$countercolor++;
		$mycolors[$countercolor] = "lred";
		$countercolor++;
		$mycolors[$countercolor] = "lblue";
		$countercolor++;
		$mycolors[$countercolor] = "lgreen";
		$countercolor++;
		$mycolors[$countercolor] = "lgray";
		$countercolor++;
		$mycolors[$countercolor] = "lyellow";
		$countercolor++;
		$mycolors[$countercolor] = "lpurple";
		$countercolor++;
		$mycolors[$countercolor] = "lorange";
		$countercolor++;
		$mycolors[$countercolor] = "lbrown";
		$countercolor++;
	}

}
