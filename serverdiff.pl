#!/usr/bin/perl -w
#
use strict;
use warnings; 

use Data::Dumper;
use Term::ANSIColor qw(:constants);

# key variables
my $verbose = 0;
my $MYDATADIR; my $STATIC; my $FIRSTSTATICFILE; my $LASTSTATICFILE; my $CONREP; my $ASU;
my $HP = 0; my $IBM = 0;
my $timestamp;

my $TODAY; my $NOW;

my $hostnam; 
my $hypert; my $ht;
my $memtot; my $rhel; my $rhelminor; my $rhelcomplete;
my $numcores; my @activenics; my $total_nics; my %test_nic; my @list_disks; my $total_disks;
my $nicextralegend = "";
my $dateofdata;
my $simple; my $config_file; my @staticfile; my $lvm = 0;
my $conrep_simple; my $conrep_config;


my %first_static; my %last_static; my %diff;

# deprecated variables to be removed
my %actualkernelparam; my @term_collector; my %actualasuparam; my %first_dynamic; my $FIRSTDYNAMIC;
my %last_dynamic; my $LASTDYNAMIC;

# Finally executing the code
&main();

# my subroutines - main as a first
sub main {

	if ((! exists $ARGV[0]) || (! exists $ARGV[1])) {
		&usage;
	}

	&sanity_check_arguments();

	$FIRSTSTATICFILE = $ARGV[0] ;
	$LASTSTATICFILE = $ARGV[1] ;

	%first_static = loading_static_data($FIRSTSTATICFILE);
#	print Dumper (\%first_static);
#	print Dumper (\%{$first_static{network}});
	%last_static = loading_static_data($LASTSTATICFILE);
#	print Dumper (\%last_static);
#	print Dumper (\%{$last_static{network}});

	compare_hashes(\%first_static, \%last_static);
	print Dumper (\%diff);

}

sub usage {
	print RED, "Server diff tool compares two servers unsing citihpc forensics collector data:\n\n\t$0 <citihpc-forensic-collector-staticfile 1>  <citihpc-forensic-collector-staticfile 2> [-v]\n", RESET;
	exit;
}

sub sanity_check_arguments {

	my $key; my $output;

	if ( -d $ARGV[0]) {
		print RED, "Error: I need a file, not a directory.\n", RESET
		exit 4;
	}

	if (! -f $ARGV[0]) {
		print RED, "Error: $ARGV[0] is not a file !\n", RESET;
		&usage;
		exit 1;
	}

	if (! -f $ARGV[1]) {
		print RED, "Error: $ARGV[1] is not a file !\n", RESET;
		&usage;
		exit 1;
	}

	foreach $key (@ARGV) {
		next unless ( -f $key );
		$output = `grep "Info: CATE CitiHPC Forensic" $key`; chomp ($output);
		if ($output eq "" ) {
			print RED, "Error: $key is not a CitiHPC Forensic file !\n", RESET;
			exit 2;
		}
	}

	
}

sub loading_static_data {

	my %static_data; $static_data{hardware}{totalmemory} = 0;
	my $file = $_[0];
	print BLUE, "Debug: Starting to parse and load static data from $file \n", RESET if ($verbose);
	
	my @tempkernelvalue; my $counter; my $kernelparam; my $asuparam;
	my $nicring; my $flag_rpm = 0 ; my $flag_system_info = 0; my $flag_network_driver = 0; my $nicdriver = 0; my $tempdriver;
	my $maximum = 0; my $key;

	my @staticfileline;
	# will parse the static file and fill a bunch of temp variables for later conditions
	@staticfileline = `cat $file`;
	foreach (@staticfileline) {

		# getting basic info from the host: hostname
		if (/^Linux((.*)\s(.*))\s\#.*Linux/) {
			$static_data{hostname} = $2;
			$static_data{os}{kernel} = $3;
		}

		if (/^Red\sHat.*\srelease\s(\d)\.(\d)\s+\(.*/) {
			$static_data{os}{vendor} = "RHEL";
			$static_data{os}{major} = $1;
			$static_data{os}{minor} = $2;
			$static_data{os}{complete} = "RHEL$1.$2";
		}

		if (/^(kernel|vm|fs|dev|net|abi|crypto|sunrpc\.)(.*)\s=\s(.*)\n/) {
			# sometimes the kernel value can be multiple numbers or words
			@tempkernelvalue = split (/\s+/, $3);
			$kernelparam = "$1"."$2";
			# if the values are indeed an array, treat as such
				$counter = 0;
				foreach (@tempkernelvalue) {
					$static_data{os}{kernelparameters}{$kernelparam}[$counter] = "$_";
					$counter++;
				}
		}

		# adding packages
		$flag_rpm = 1 if (/^Info:\srpm\s\-qa/);
		if ($flag_rpm) {
			if (/^Info:\send\sof\srpm\s\-qa/) { 
				$flag_rpm = 0;
				next;
			} else {
				$static_data{os}{packages}{$1} = $3 if (/(\w+(-\w+)?)-(\d+\.\d+.*)/);
			}
		}
		
		# hardware 

		if (/^\s+Size:\s(\d+)\sMB/) {
			$static_data{hardware}{memorysizes} = $1;
			$static_data{hardware}{totalmemory} = $static_data{hardware}{totalmemory} + $1;
		}
		$static_data{hardware}{memoryspeeds} = $1 if (/^\s+Speed:\s(\d+\sMHz)/);

		# getting the machine type/model
		$flag_system_info = 1 if (/^System\sInformation/);
		if ($flag_system_info) {
			# in case there is Manufactuter, override previous settings
			$static_data{hardware}{machinevendor} = $1 if (/\s+Manufacturer:\s(.*)/);
			# finding out if it is a blade, etc
			if (/\s+Product\sName:\s(.*)/) {
				$static_data{hardware}{model} = $1;
				$flag_system_info = 0; 
			}
		}

		$static_data{hardware}{cpumodel} = $1 if (/model\s+name\s+:\s(\w.*)/);

		#detecting the number of CPUs
		$static_data{hardware}{totalnumcores} = ($1+1) if (/^processor\s+:\s(\d+)/); 

		# finding out about  hyperthreading - cpu cores and simblings must match
		$static_data{hardware}{corespersocket} = $1 if (/^cpu\scores\s+:\s+(\d+)/);
		$static_data{hardware}{cpusiblings} = $1 if (/^siblings\s+:\s+(\d+)/);

		# network

		# detecting active NICs - from ip addr command 
#		$static_data{network}{$1}{activenic} = 1 if (/^\s+inet.*global\s(eth\d)/);
		$static_data{network}{nic}{$1}{mtu} = $2 if (/.*(eth\d):.*BROADCAST.*mtu\s(\d+)\sqdisc/); 

		#bond stuff
		if (/.*(eth\d):.*SLAVE.*mtu\s(\d+).*\smaster\s(bond\d)/) {
#			 $static_data{network}{$1}{activenic} = 1;
#			 $static_data{network}{$1}{slaveof} = $3;
			 $static_data{network}{nic}{$1}{mtu} = $2;
			 $static_data{network}{nic}{$3}{driver} = "bondinterface";

		}
		# just double chcking bond info
		$static_data{network}{nic}{$1}{activenic} = 1 if (/\s+inet.*global\s(bond\d)/);

		# nic drivers
		$flag_network_driver = 1 if (/^Info: ethtool\s\-i/);
		if ($flag_network_driver) {
			$nicdriver = $1 if (/(eth\d)/);
			if (/driver:\s+(.*)/) {
				$tempdriver = $1;
				$static_data{network}{nic}{$nicdriver}{driver} = $tempdriver;
				$static_data{network}{driver}{$tempdriver}{driver} = $tempdriver;
			}
			$static_data{network}{driver}{$tempdriver}{version} = $1 if (/^version:\s+(.*)/);
			$static_data{network}{driver}{$tempdriver}{firmware} = $1 if (/firmware-version:\s+(.*)/);
		}
		$flag_network_driver = 0 if (/^Info: end of ethtool\s\-i/);


		# nic ring buffers - the output is tricky because the "Pre-set" and "Current" have the same format
		$nicring = $1 if (/^Ring\sparameters\sfor\s(eth\d):/);
		$maximum = 1 if (/^Pre-set\smaximums:/);
		$maximum = 0 if (/^Current\shardware\ssettings:/);
		if ($maximum) {
			$static_data{network}{nic}{$nicring}{ringbuffersrxmax} = $1 if (/^RX:\s+(\d+)\n/);
			$static_data{network}{nic}{$nicring}{ringbufferstxmax} = $1 if (/^TX:\s+(\d+)\n/);

		} else {
			$static_data{network}{nic}{$nicring}{ringbuffersrxcurrent} = $1 if (/^RX:\s+(\d+)\n/);
			$static_data{network}{nic}{$nicring}{ringbufferstxcurrent} = $1 if (/^TX:\s+(\d+)\n/);

		}

		# bios stuff - HP bios is in a separate file need to add a separate routine for that
		# IBM ASU paramters (when present)

		if (/^(IMM|SYSTEM_PROD_DATA|BootOrder|iSCSI|PXE|uEFI\.)(.*)=(.*)\n/) {
			# sometimes the kernel value can be multiple numbers or words
			$asuparam = "$1"."$2";
			$static_data{bios}{$asuparam} = $3;

		}

		# finding logical volume and disks
		$static_data{misc}{lvm} = 1 if (/Logical\s[vV]olume/);	
		$static_data{misc}{disk}{$1}{size} = $2 if (/^Disk\s(.*):\s(\d+\.\d+)\s[MG]B.*/);

		
		$static_data{misc}{tcpsegmentationoff} = 1 if (/^tcp-segmentation-offload:\s+off/);
		$static_data{misc}{genericsegmentationoff} = 1 if (/^generic-segmentation-offload:\s+off/);

		$static_data{miscarray}{nameserver}{$1} = 1 if (/nameserver\s(\d+\.\d+\.\d+\.\d+)/);	

	}


	# final checks and loads
	# hyperthread check
#	if ( $static_data{hardware}{tempcpucores} eq $static_data{hardware}{tempcpusiblings} )  {
#		$static_data{os}{hyperthreading} = "off";
#	} else {
#		$static_data{os}{hyperthreading} = "on";
#	}

#	print Dumper (\%static_data);

	return %static_data;

}

sub compare_hashes(\%\%) {

	my %hbase; %hbase = %{$_[0]};
	my %hcomp; %hcomp = %{$_[1]};
	my $key1; my $key2; my $key3; my $key4;
	my $nic; my $bondnic;
	my $base; $base = $hbase{hostname};
	my $comp; $comp = $hcomp{hostname};

	foreach $key1 (sort (keys(%hbase))) {

		next if ($key1 eq "hostname");

		if ($key1 eq "os") {

			if ($hbase{$key1}{vendor} ne $hcomp{$key1}{vendor}) {
				$diff{$key1}{vendor}{$base} = $hbase{$key1}{vendor};
				$diff{$key1}{vendor}{$comp} = $hcomp{$key1}{vendor};
				next;
			}
			if ($hbase{$key1}{major} eq $hcomp{$key1}{major}) {

				compare_kernel(\%{$hbase{$key1}{kernelparameters}}, \%{$hcomp{$key1}{kernelparameters}}, $base, $comp) ;

				if ($hbase{$key1}{minor} eq $hcomp{$key1}{minor}) {
					compare_packages(\%{$hbase{$key1}{packages}}, \%{$hcomp{$key1}{packages}}, $base, $comp) ;
					# compare packages
				} else {
					print RED, "Info: Minor OS releases different, skipping packages comparison.\n", RESET;
					$diff{$key1}{complete}{$base} = $hbase{$key1}{complete};
					$diff{$key1}{complete}{$comp} = $hcomp{$key1}{complete};
					next;

				}	

			} else {
				print RED, "Info: Major OS releases different, skipping kernel parameters and packages comparison.\n", RESET;
				$diff{$key1}{complete}{$base} = $hbase{$key1}{complete};
				$diff{$key1}{complete}{$comp} = $hcomp{$key1}{complete};
				next;
			}

		}

		if ($key1 eq "hardware") {
			foreach $key2 (sort (keys(%{$hbase{$key1}}))) {
				if ( ! exists  $hcomp{$key1}{$key2} ) {
						$diff{$key1}{$key2}{$base} = $hbase{$key1}{$key2};
						$diff{$key1}{$key2}{$comp} = undef;
				} else {
					if ($hbase{$key1}{$key2} ne $hcomp{$key1}{$key2}) {
						$diff{$key1}{$key2}{$base} = $hbase{$key1}{$key2};
						$diff{$key1}{$key2}{$comp} = $hcomp{$key1}{$key2};
					}
				}
			}

		}


		if ($key1 eq "network") {
			foreach $key2 (sort (keys(%{$hbase{network}{driver}}))) {
				next unless exists $hbase{network}{driver}{$key2}{driver};
				if ( ! exists  $hcomp{network}{driver}{$key2} ) {
						$diff{$key1}{driver}{$key2}{$base} = $hbase{$key1}{driver}{$key2}{driver};
						$diff{$key1}{driver}{$key2}{$comp} = "notpresent";
				} else {
					if ($hbase{$key1}{driver}{$key2}{driver} eq $hcomp{$key1}{driver}{$key2}{driver}) {
						# will compare only if the nics are the same...
						foreach $key3 (sort (keys %{$hbase{network}{driver}{$key2}})) {
							if ($hbase{$key1}{driver}{$key2}{$key3} ne $hcomp{$key1}{driver}{$key2}{$key3}) {
								$diff{$key1}{driver}{$key2}{$key3}{$base} = $hbase{$key1}{driver}{$key2}{$key3};
								$diff{$key1}{driver}{$key2}{$key3}{$comp} = $hcomp{$key1}{driver}{$key2}{$key3};
							}
						}
						# compare NIC
					} else {
						$diff{$key1}{driver}{$key2}{$base} = $hbase{$key1}{driver}{$key2}{driver};
						$diff{$key1}{driver}{$key2}{$comp} = $hcomp{$key1}{driver}{$key2}{driver};
					}
				}
			}
			foreach $key2 (sort (keys(%{$hcomp{network}{driver}}))) {
				if (! exists $hbase{network}{driver}{$key2}{driver}) {
					$diff{$key1}{driver}{$key2}{$base} = "notpresent";
					$diff{$key1}{driver}{$key2}{$comp} = $hcomp{$key1}{driver}{$key2}{driver};

				}
			}

		}
#		if (ref $hbase{$key1} eq 'HASH') {
#			foreach $key2 (sort (keys(%{$hbase{$key1}}))) {
#				if (ref $hbase{$key1}{$key2} eq 'HASH') {
#					foreach $key3 (sort (keys(%{$hbase{$key1}{$key2}}))) {
#					print " $key1 $key2 $key3 $hbase{$key1}{$key2}{$key3}\n";
#						if ($hbase{$key1}{$key2}{$key3} ne $hcomp{$key1}{$key2}{$key3}) {
#							$diff{$key1}{$key2}{$key3}{$base} = $hbase{$key1}{$key3}{$key2};
#							$diff{$key1}{$key2}{$key3}{$comp} = $hcomp{$key1}{$key3}{$key2};
#						}
#
#					}
#
#				} else {
#					print " $key1 $key2 $hbase{$key1}{$key2}\n";
#					if ($hbase{$key1}{$key2} ne $hcomp{$key1}{$key2}) {
#						$diff{$key1}{$key2}{$base} = $hbase{$key1}{$key2};
#						$diff{$key1}{$key2}{$comp} = $hcomp{$key1}{$key2};
#					}
#				}
#			}
#		} else {
#			if ($hbase{$key1} ne $hcomp{$key1}) {
#				$diff{$key1}{$base} = $hbase{$key1};
#				$diff{$key1}{$comp} = $hcomp{$key1};
#
#			}
#
#		}
	}

#	return (%diff);

}

sub compare_kernel {
	my %kernelbase = %{$_[0]};
	my %kernelcomp = %{$_[1]};
	my $base = $_[2];
	my $comp = $_[3];
	my $key, my $arraysize; my $counter;
	foreach $key (sort (keys %kernelbase)) {
	#	print BLUE, "Debug: checking $key ... \n", RESET if ($verbose);
		next if ($key =~ /eth\d/);
		next if ($key =~ /bond\d/);
		next if ($key =~ /hostname/);
		next if ($key =~ /random/);
		next if ($key =~ /net\.ipv6\.conf/);
		next if ($key =~ /net\.ipv6\.neigh/);
		next if ($key =~ /net\.ipv6\.route/);
		if (exists $kernelcomp{$key}) {
			# check if the paramer is multi value
			$arraysize = @{$kernelbase{$key}};
			for ($counter = 0; $counter < $arraysize; $counter++) {
				if ($kernelbase{$key}[$counter] ne $kernelcomp{$key}[$counter]) {
					$diff{os}{kernelparameter}{$key}{$base} = $kernelbase{$key}[$counter];
					$diff{os}{kernelparameter}{$key}{$comp} = $kernelcomp{$key}[$counter];
				}
			}
		} else {
			$diff{os}{kernelparameter}{$key}{$base} = $kernelbase{$key}[0];
			$diff{os}{kernelparameter}{$key}{$comp} = undef;
		}
	}
}

sub compare_packages {
	my %packagesbase = %{$_[0]};
	my %packagescomp = %{$_[1]};
	my $base = $_[2];
	my $comp = $_[3];
	my $key, my $arraysize; my $counter;
	foreach $key (sort (keys %packagesbase)) {
	#	print BLUE, "Debug: checking $key ... \n", RESET if ($verbose);
		if (! exists $packagescomp{$key}) {
			$diff{os}{packages}{$key}{$comp} = "notpresent";
			$diff{os}{packages}{$key}{$base} = $packagesbase{$key};
		} else {
				if ($packagesbase{$key} ne $packagescomp{$key}) {
					$diff{os}{packages}{$key}{$base} = $packagesbase{$key};
					$diff{os}{packages}{$key}{$comp} = $packagescomp{$key};
				}

		}
	}
	foreach $key (sort (keys %packagescomp)) {
		if (! exists $packagesbase{$key}) {
			$diff{os}{packages}{$key}{$base} = "notpresent";
			$diff{os}{packages}{$key}{$comp} = $packagescomp{$key};
		}
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

