#!/usr/bin/perl -w
#
# Heatmap generator
# created 06/27/2014
#
use strict;
use warnings; 

use Data::Dumper;
use GD;
use GD::Graph::Data;
use GD::Graph::lines;
use GD::Graph::mixed;


# other variables
my $timestamp;
my @linex;
my @liney;

my @linethreshold;
my @linedata;

my $hostnam;
my $hypert;
my $memtot; my $rhel; my $numcores; my @activenics; my $total_nics; my %test_nic; my @list_disks; my $total_disks;
my $nicextralegend = "";
my $dateofdata;

my $graphdat; $graphdat = "graph.forensic.dat";
my $graphdatmem; $graphdatmem = "graph.forensic.mem.dat";
my $graphdatnic; $graphdatnic = "graph.forensic.nic.dat";
my $graphdatdiskawait; $graphdatdiskawait = "graph.forensic.disk.await.dat";
my $graphdatdiskcpu; $graphdatdiskcpu = "graph.forensic.disk.cpu.dat";
my $graphdatdiskread; $graphdatdiskread = "graph.forensic.disk.read.dat";
my $graphdatdiskwrite; $graphdatdiskwrite = "graph.forensic.disk.write.dat";

my $verticalsize; my $horizontalsize; my $numofdynfiles;
my $verticalsizedisk; 

# large array references for the graphs
my @mytype; my @mycolors; my @mytypecpu; my @mycpulegend;
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

# Finally executing the code
&main();

# my subroutines - main as a first
sub main {

	&gettingbasicinfo();
	&parsing_log();
	&creating_line_graph ();
	&creating_mem_graph ();
#	&creating_nic_graph ();
	&creating_diskawait_graph ();
	&creating_diskcpu_graph ();
	&creating_diskread_graph ();
	&creating_diskwrite_graph ();

}

sub gettingbasicinfo {

	# getting basic info from the host: hostname
	$hostnam = `grep hostname $ARGV[0]/static-* | awk '{print \$3}' | head -1`; chomp ($hostnam);

	# date of collection
	my $tempdate = `grep CitiHPC  $ARGV[0]/static-* | tail -1`; chomp ($tempdate);
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
	# finding rhel release
	my $rhelrelease = `grep ^"Red Hat Enterprise"  $ARGV[0]/static-* | head -1`;
	if ($rhelrelease =~ /Santiago/) {
		$rhel = "6";
	} else {
		$rhel = "5";
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
#
	# creating the size of the graph depending of the number of disks or samples - some servers have 200+ disks
	$numofdynfiles = `ls $ARGV[0]/dynamic-* | wc -l`; chomp ($numofdynfiles);

	if ($numofdynfiles < 1100) {
		$horizontalsize=1200;		
		$verticalsize=600;		
	} else {
		$horizontalsize=$numofdynfiles+100;		
		$verticalsize=600;		
	}

	# disk requires a talled graph if there is so many of them
	if ($total_disks < 160) {
		$verticalsizedisk=600;		
	} else {
		$verticalsizedisk=1500;		
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

	# adding the logo
	my $logo = GD::Image->newFromPng('logo-citihpc.png');
	my ($w, $h) = $logo->getBounds( );
	$linegraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);

	my $pnglinefile="citihpc-forensic-heatmap-cpu-$hostnam.png";
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
		types		=>  [qw(area area area bars)],
		dclrs		=>  [qw(green red blue gray)],
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
	$mymemgraph->set_legend(qw (FREE USED BUFFERS SHARED));

	my $memgraph = $mymemgraph->plot($datamem) or die $mymemgraph->error;

	# adding the logo
	my $logo = GD::Image->newFromPng('logo-citihpc.png');
	my ($w, $h) = $logo->getBounds( );
	$memgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);

	my $pngmemfile="citihpc-forensic-heatmap-mem-$hostnam.png";
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
	      title             => "NIC utilization in Kbps - server $hostnam $nicextralegend  - $dateofdata",
		dclrs		=> @listofcolors,
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
	      y_label           => 'Kbps',
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

	# adding the logo
	my $logo = GD::Image->newFromPng('logo-citihpc.png');
	my ($w, $h) = $logo->getBounds( );
	$nicgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);

	my $pngnicfile="citihpc-forensic-heatmap-nic-$hostnam.png";
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
	      title             => "Disk await in ms - server $hostnam  - $dateofdata",
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

	# adding the logo
	my $logo = GD::Image->newFromPng('logo-citihpc.png');
	my ($w, $h) = $logo->getBounds( );
	$diskagraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);

	my $pngdiskafile="citihpc-forensic-heatmap-disk-await-$hostnam.png";
	open(IMG, ">$pngdiskafile") or die $!;
	binmode IMG;
	print IMG $diskagraph->png;
}

sub creating_diskcpu_graph {

	my $datadiskc = GD::Graph::Data->new();
	$datadiskc->read(file=> $graphdatdiskcpu);

	my $mydiskcgraph = GD::Graph::mixed->new($horizontalsize, $verticalsizedisk) or die "Can't create graph!";

	$mydiskcgraph->set(
	      title             => "%CPU used for IO - server $hostnam  - $dateofdata",
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

	# adding the logo
	my $logo = GD::Image->newFromPng('logo-citihpc.png');
	my ($w, $h) = $logo->getBounds( );
	$diskcgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);

	my $pngdiskcfile="citihpc-forensic-heatmap-disk-cpu-$hostnam.png";
	open(IMG, ">$pngdiskcfile") or die $!;
	binmode IMG;
	print IMG $diskcgraph->png;
}

sub creating_diskread_graph {

	my $datadiskr = GD::Graph::Data->new();
	$datadiskr->read(file=> $graphdatdiskread);

	my $mydiskrgraph = GD::Graph::mixed->new($horizontalsize, $verticalsizedisk) or die "Can't create graph!";

	$mydiskrgraph->set(
	      title             => "Disk Reads in Mb/sec - server $hostnam  - $dateofdata",
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
	      y_label           => 'Mb/sec',
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

	# adding the logo
	my $logo = GD::Image->newFromPng('logo-citihpc.png');
	my ($w, $h) = $logo->getBounds( );
	$diskrgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);

	my $pngdiskrfile="citihpc-forensic-heatmap-disk-read-$hostnam.png";
	open(IMG, ">$pngdiskrfile") or die $!;
	binmode IMG;
	print IMG $diskrgraph->png;
}

sub creating_diskwrite_graph {

	my $datadiskw = GD::Graph::Data->new();
	$datadiskw->read(file=> $graphdatdiskwrite);

	my $mydiskwgraph = GD::Graph::mixed->new($horizontalsize, $verticalsize) or die "Can't create graph!";

	$mydiskwgraph->set(
	      title             => "Disk Writes in Mb/sec - server $hostnam  - $dateofdata",
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
	      y_label           => 'Mb/sec',
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

	# adding the logo
	my $logo = GD::Image->newFromPng('logo-citihpc.png');
	my ($w, $h) = $logo->getBounds( );
	$diskwgraph->copy($logo, $horizontalsize-90, 5, 0, 0, $w, $h);

	my $pngdiskwfile="citihpc-forensic-heatmap-disk-write-$hostnam.png";
	open(IMG, ">$pngdiskwfile") or die $!;
	binmode IMG;
	print IMG $diskwgraph->png;
}
