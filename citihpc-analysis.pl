#!/usr/bin/perl -w
#
use strict;
use warnings; 

use Data::Dumper;
use Term::ANSIColor qw(:constants);


# key variables
my $verbose = 0;
my $MYDATADIR; my $STATIC; my $FIRSTDYNAMIC; my $LASTDYNAMIC;
my $timestamp;

my $TODAY; my $NOW;

my $hostnam; 
my $hypert;
my $memtot; my $rhel; my $numcores; my @activenics; my $total_nics; my %test_nic; my @list_disks; my $total_disks;
my $dateofdata;


# Finally executing the code
&main();

# my subroutines - main as a first
sub main {

	if (undef $ARGV[0]) {
		&usage;
	}
	&display_header();
	&checking_datadir();
	&gettingbasicinfo();
	&parsing_log();

}

sub usage {
	print RED, "Usage: $0 <citihpc-forensic-data-directory>.Specifiy the path of the citihpc forensic collector data directory.\n", RESET;
	exit;
}

sub display_header {

	$TODAY=`date +%y%m%d`; chomp ($TODAY);
	$NOW=`date +%y%m%d-%H%M%S`; chomp ($NOW);

	$user=`id | awk 'BEGIN { FS="("} { print \$2}' | awk 'BEGIN { FS=")"} {print \$1}'`; chomp($user);


	print GREEN, "Info: Starting Citi HPC Low Latency Analysis on $TODAY at $NOW\n", RESET;
	print GREEN, "Info: User $user is executing the script.\n", RESET;

}

sub checking_datadir {

	if (-d $ARG[0]) {
		$MYDATADIR = $ARGV[0];	
	} else {
		print RED, "Error: could not open data directory $ARGV[0] !\n", RESET;
		usage;
		exit 2;
	}

	if ($ARGV[1] eq "-v") {
		$verbose=1;
		print GREEN, "Info: Verbose Mode is ON.\n", RESET;
	}

	$STATIC=`ls ${MYDATADIR}/static* 2>/dev/null | head -1 2>/dev/null`; chomp($STATIC);

	if ! (-f $STATIC) {
		print RED, "Error: Could not find static file on $MYDATADIR data directory!\n", RESET;
		usage;
		exit 3;
	} else {

		print GREEN,"Info: Data directory is $MYDATADIR\n",RESET if ($verbose);
	}

	my $compress=`ls ${MYDATADIR}/dynamic*gz | wc -l`; chomp ($compress);

	if ($compress < 2) {
		print RED, "Error: Dynamic Files cannot be found or are not compressed!\n", RESET;
		usage;
		exit 6;
	} else {
		print GREEN,"Info: Found $compress dynamic files under $MYDATADIR\n",RESET if ($verbose);
	}

	$FIRSTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | head -1 2>/dev/null`; chomp($FIRSTDYNAMIC);

	if ! (-f $FIRSTDYNAMIC) {
		print RED, "Error: Could not find dynamic file on $MYDATADIR data directory!\n", RESET;
		usage;
		exit 3;
	} else {
		print GREEN,"Info: The first dynamic file found is $FIRSTDYNAMIC\n",RESET if ($verbose);
	}

	$LASTDYNAMIC=`ls ${MYDATADIR}/dynamic*gz 2>/dev/null | tail -2 | head -1`; chomp($LASTDYNAMIC);

	if ! (-f $LASTDYNAMIC) { 
		print RED, "Error: Could not find dynamic file on $MYDATADIR data directory!\n", RESET;
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

	if ($rhelrelease =~ /^Red\sHat.*\s6\.\d?/) {
		$rhel = "6";
	} else {
		$rhel = "5";
	}

	print GREEN, "Info: $hostname RHEL$rhel \n";
	# date of collection
	my $tempdate = `grep CitiHPC  $STATIC | tail -1`; chomp ($tempdate);
	$dateofdata = "$1/$2/$3" if ($tempdate =~ /on\s(\d\d)(\d\d)(\d\d)\sat/);
	# finding out if hyperthreading is on or off - useful for the CPU graph
	# on RHEL5 is difficult to detect hyperthreading because there is no "lscpu"
	my $tempht = `grep 'per core:' $ARGV[0]/static-* | awk -F: '{print \$2}' | head -1`;
	if ( $tempht =~ /2/ )  {
		$hypert = "(Hyperthreading is ON)";
	} else {
		if ( $tempht =~ /1/ ) {
			$hypert = "(Hyperthreading is OFF)";
		} else {
			$hypert = "";
		}
	}
	# detecting the number of CPUs
	$numcores = `grep ^processor  $ARGV[0]/static-* | tail -1 | awk '{print \$3}'`; chomp($numcores);
	# detecting active NICs - from ip addr command
	my @tempactivenics = `grep inet $ARGV[0]/static-* | grep global | awk '{print \$NF}'`;
	for (@tempactivenics) {
		chomp;
		if (/bond/) {
			# i need to make an extra step
			$nicextralegend = "(bonded NICs)";
			my @bondedinterfaces = `grep master $ARGV[0]/static-* | grep $_ | awk '{print \$2}' | awk -F: '{print \$1}'`;
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
	#detecting the list of disks - they must be have "*vg-*" on it
	my $dynamicfile = `ls $ARGV[0]/dynamic-*gz | tail -1`; chomp $dynamicfile;
	my @temp_list_disks = `zcat $dynamicfile`; my %temp_disk;
	for (@temp_list_disks) {
		if (/^Average:\s+(\w+vg-\w+|dev\d+-\d+)\s+\d+\.*/){
			$temp_disk{$1} = 1;
		}
	}
	@list_disks = sort keys (%temp_disk); $total_disks = @list_disks;
#	print Dumper(\@list_disks);

	# creating the size of the graph depending of the number of disks - some servers have 200+ disks
	if ($total_disks < 160) {
		$verticalsize=600;		
		$horizontalsize=1200;		

	} else {
		$verticalsize=1500;		
		$horizontalsize=3000;		
	}

}


sub parsing_log {
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
