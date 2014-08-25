#!/usr/bin/perl -w
#
use strict;
use warnings; 

use Data::Dumper;
use Term::ANSIColor qw(:constants);
use XML::Simple;


# key variables
my $verbose = 0;
my $MYDATADIR; my $STATIC; my $FIRSTDYNAMIC; my $LASTDYNAMIC;
my $timestamp;
my @term_collector;

my $TODAY; my $NOW;

my $hostnam; 
my $hypert; my $ht;
my $memtot; my $rhel; my $numcores; my @activenics; my $total_nics; my %test_nic; my @list_disks; my $total_disks;
my $dateofdata;
my $simple; my $config_file; my @staticfile; my $lvm = 0;

my $graphdat; $graphdat = "graph.forensic.dat"; 
my $graphdatmem; $graphdatmem = "graph.forensic.mem.dat"; 
my $graphdatnic; $graphdatnic = "graph.forensic.nic.dat"; 
my $graphdatdiskawait; $graphdatdiskawait = "graph.forensic.disk.await.dat"; 
my $graphdatdiskcpu; $graphdatdiskcpu = "graph.forensic.disk.cpu.dat"; 
my $graphdatdiskread; $graphdatdiskread = "graph.forensic.disk.read.dat"; 
my $graphdatdiskwrite; $graphdatdiskwrite = "graph.forensic.disk.write.dat"; 
 
my %actualkernelparam;


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
#	&parsing_dynamic();

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

		print BLUE,"Debug: Data directory is $MYDATADIR\n",RESET if ($verbose);
	}

	my $compress=`ls ${MYDATADIR}/dynamic*gz | wc -l`; chomp ($compress);

	if ($compress < 2) {
		print RED, "Error: Dynamic Files cannot be found or are not compressed!\n", RESET;
		usage;
		exit 6;
	} else {
		print BLUE,"Debug: Found $compress dynamic files under $MYDATADIR\n",RESET if ($verbose);
	}

	$FIRSTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | head -1 2>/dev/null`; chomp($FIRSTDYNAMIC);

	if ( ! -f $FIRSTDYNAMIC) {
		print RED, "Error: Could not find first dynamic file on $MYDATADIR data directory!\n", RESET;
		usage;
		exit 3;
	} else {
		print BLUE,"Debug: The first dynamic file found is $FIRSTDYNAMIC\n",RESET if ($verbose);
	}

	$LASTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | tail -2 | head -1`; chomp($LASTDYNAMIC);

	if ( ! -f $LASTDYNAMIC) { 
		print RED, "Error: Could not find last dynamic file on $MYDATADIR data directory!\n", RESET;
		usage;
		exit 3;
	} else {
		print BLUE,"Debug: The last dynamic file found is $LASTDYNAMIC\n",RESET if ($verbose);
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

	if ($rhelrelease =~ /^Red\sHat.*\s6\.\d?/) {
		$rhel = "6";
	} else {
		$rhel = "5";
	}

	# date of collection
	my $tempdate = `grep CitiHPC  $STATIC | tail -1`; chomp ($tempdate);
	$dateofdata = "$1/$2/$3" if ($tempdate =~ /on\s(\d\d)(\d\d)(\d\d)\sat/);

	print GREEN, "Info: Collector data from $dateofdata for hostname $hostnam , RHEL$rhel version\n", RESET;

}

sub reading_config {
	$simple = XML::Simple->new(); 
	$config_file = $simple->XMLin('./citihpc-analysis.xml'); 
#	print Dumper($config_file);
}

sub parsing_static {

	my @tempactivenics; my $tempcpucores; my $tempcpusiblings; my @tempmemsize; my @tempmemspeed;
	my @tempbroadcom; my @tempkernelvalue; my $counter; my $kernelparam;
	my $arraycounter;

	# will parse the static file and fill a bunch of temp variables for later conditions
	print BLUE, "Debug: Starting to parse static data\n", RESET if ($verbose);
	@staticfile = `cat $STATIC`;
	foreach (@staticfile) {
		#detecting the number of CPUs
		$numcores = ($1+1) if (/^processor\s+:\s(\d+)/); 

		# detecting active NICs - from ip addr command - filling a temp array
		push (@tempactivenics, $1) if (/^\s+inet.*global\s(eth\d|bond\d)/);

		# finding out if hyperthreading is on, cpu cores and simblings must match
		$tempcpucores = $1 if (/^cpu\scores\s+:\s+(\d+)/);
		$tempcpusiblings = $1 if (/^siblings\s+:\s+(\d+)/);

		# finding logical volume
		$lvm = 1 if (/Logical Volume/);	

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
	}

	#print Dumper (\%tempkernelparam);

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
		print BLUE, "Debug: Currently, hyper-threading is $ht because server has $tempcpucores cores and $tempcpusiblings siblings\n", RESET;
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
		push (@term_collector, "Non uniform memory size has been detected which may lead to unpredictable speed and memory access!\n");
	} else {
		print BLUE, "Debug: Memory Size is uniform in $tempmemsize[0] Mb\n", RESET if ($verbose);
	}

	@uniqarray = uniq ( @tempmemspeed );
	$arraycounter = @uniqarray;
	if ($arraycounter > 1) {
		print RED, "Warning: Memory Speed Not Uniform across memory devices!\n", RESET if ($verbose);
		push (@term_collector, "Memory Speed is not uniform across the memory devices which may result in performance degradation!\n");
	} else {
		print BLUE, "Debug: Memory Speed is uniform in $tempmemspeed[0] MHz\n", RESET if ($verbose);
	}
	

	# parsing the activenics
#	print Dumper (\@tempactivenics);
	for (@tempactivenics) {
		chomp;
		if (/bond/) {
			# i need to make an extra step - need to improve this code big time, doing another grep
			my $nicextralegend = "(bonded NICs)";
			my @bondedinterfaces = `grep master $STATIC | grep $_ | awk '{print \$2}' | awk -F: '{print \$1}'`;
			for (@bondedinterfaces) {
				chomp;
				$test_nic{$_} = 1;
			}

		} else {
			$test_nic{$_} = 1;
		}
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
			push (@term_collector, "Broadcom NIC has been detected in use on the system for interface $_.Not a favoured vendor!\n");
		}
	}

	&checking_kernel;
	
	#
#	#detecting the list of disks - they must be have "*vg-*" on it - this data is only on dynamic
	my @temp_list_disks = `zcat $LASTDYNAMIC`; my %temp_disk;
	for (@temp_list_disks) {
		if (/^Average:\s+(\w+vg-\w+|dev\d+-\d+)\s+\d+\.*/){
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
		 push (@term_collector, "Kernel Parameters are not finely tuned for low latency or intense compute application!\n");

	}
}


sub parsing_dynamic {
	my @listfiles;
	@listfiles = `ls $ARGV[0]/dynamic*gz`;
	open (my $fh, '>', $graphdat) or die "Could not open file '$graphdat' $!";
	open (my $fhmem, '>', $graphdatmem) or die "Could not open file '$graphdatmem' $!";
	open (my $fhnic, '>', $graphdatnic) or die "Could not open file '$graphdatnic' $!";
	open (my $fhdiska, '>', $graphdatdiskawait) or die "Could not open file '$graphdatdiskawait' $!";
	open (my $fhdiskcpu, '>', $graphdatdiskcpu) or die "Could not open file '$graphdatdiskcpu' $!";
	open (my $fhdiskread, '>', $graphdatdiskread) or die "Could not open file '$graphdatdiskread' $!";
	open (my $fhdiskwrite, '>', $graphdatdiskwrite) or die "Could not open file '$graphdatdiskwrite' $!";
	foreach (@listfiles) {
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
					}
					next;
				}
			} else {
				if (/^Average:\s+(all|\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)/){
					# $10 is CPU idle - grpah is utilization, hence a little subtraction from "100"
					push (@datarray, sprintf("%.2f",100-$10));
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
			if (/^Average:\s+(\w+vg-\w+|dev\d+-\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)/){
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

#	print Dumper(\@datarray);

}

# the following return an uniq elements of the array
sub uniq {
  my %seen;
  return grep { !$seen{$_}++ } @_;
}

