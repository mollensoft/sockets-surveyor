# SocketsSurveyor Rflow Receiver Daemon V1
#
# When Run, receives UDP Rflow event (Netflow Version 5) Packets and send them through the SocketsSurveyor analysis system for further processing and enrichment
#
#  Thanks to David Farrell for the inspiration as this is an expansion of original concept code found in his perl blog post
#
# MIT License Copyright (c) [2018] [Mark Mollenkopf]
#
use strict;
use warnings;
use Fcntl qw(:flock);
use IO::Socket::INET;
use Data::Netflow;
use Gearman::Client;
use Cwd qw(cwd);

my $starttime = time();

########## Configuration #######################################
my $workdir = cwd; #Set Up Working Dir
my $log_dir;
$log_dir = $workdir . "/logs/"; #path to log dir default is .+log
################################################################


my $sock = IO::Socket::INET->new(
  LocalPort => 2055,  # This is the UDP Port we'll be listening on
  Proto     => 'udp'  # Make sure we specify the appropriate protocol to listen for
);



my ($sender, $datagram);
while ($sender = $sock->recv($datagram, 0xFFFF)) {

  my ($headers, $records) = Data::Netflow::decode($datagram, 1) ;
  
     # lets parse through each record in the datagram - RFLOW udp packets can contain several events within a single UDP Packet  
    for my $r (@$records) {
    
      # Lets extract the critical important fields from Version 5 of RFLOW that's built in to a DDWRT enabled router (may need to be tailored if you use other NETFLOW Versions)
      # Important Note - we are using the receiver's Date Time as the Event date time (this may change in the future) - multiple sources routers kept originating events on a differing
      #  Date-Time Scale which caused problems - the delta time has been determined to be negligible
      my $log_this = sprintf "%d,%s,%d,%s,%d,%d,%d,%d", time, $r->{SrcAddr}, $r->{SrcPort}, $r->{DstAddr}, $r->{DstPort}, $r->{Packets}, $r->{Octets}, $r->{Protocol};

      distribute_task($log_this);
      log_evt("SSd Received Rflow Event: $log_this ");
    
  }
}


sub distribute_task {
    
    # send to gearman Client, objective is to distribute tasks across many workers although I've not found a need for more than one or two given the volume of clients performing analysis of
    
    my ($invar) = @_;
    log_evt("InDistrib Sub, Sanitizing $invar");
    my $sanitized_input = sanitize_input($invar);
    log_evt("Distributing Task to Analyze $sanitized_input ..."); 
    my $client = Gearman::Client->new;
    $client->job_servers('127.0.0.1:4730');
    
    $client->dispatch_background('process_event', $sanitized_input, {});
    
    log_evt("Sent Gearman Worker Task: process_event Var: $sanitized_input");
    
}



sub log_evt {    # standard logging subroutine
 
  my ($invar) = @_;
  chomp($invar);
  my ($DAY, $MONTH, $YEAR) = (localtime)[3,4,5];
	$YEAR= $YEAR + 1900;
	$MONTH = $MONTH + 1;
	
	if ($MONTH <10) { $MONTH = "0"."$MONTH";}
	if ($DAY <10) { $DAY = "0"."$DAY";}
	my $FQDTG = "$YEAR$MONTH$DAY";
	
  my $logfile = "$log_dir" . "SocketSurveyerEventD_";
	$logfile .= "$FQDTG";
  $logfile .= ".txt";

        open my $DB, '>>', $logfile  || warn "Error Opening Current Reports File $logfile \n";
        flock $DB, LOCK_EX;
        print $DB "$invar \n";
        print "$invar\n";
        close $DB;
    
}


sub sanitize_input {  # standard input sanatization subroutine
    
    my ($dirty_invar) = @_;
    log_evt("InSanitize, Recvd: $dirty_invar !"); 
    $dirty_invar =~ s/,/\|/g;
    log_evt("Substituted , for pipes: $dirty_invar !"); 
    $dirty_invar =~ s/([;<>\*`&\$!#\(\)\[\]\{\}:'"])//g; # Allow | and . 
    $dirty_invar =~ s/[a-z]//gi; # Allow Integers
    my $sanitized_output = $dirty_invar;
    log_evt("About to Return Sanitized output $sanitized_output !"); 
    return $sanitized_output;
  
  }
