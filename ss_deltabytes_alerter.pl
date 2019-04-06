#
#  SocketsSurveyor Delta Bytes Alerter Daemon V1
#
# Performs SQL Queries looking for conditions where outbound bytes exchanged between communicants exceeds inbound bytes threshold is met or exceeded then sends Email Alert to the configured recipient
#
# This is fairly Database intensive and will be updated to Optimize Database Query Performance 
#
# MIT License Copyright (c) [2018] [Mark Mollenkopf]
#


use strict;
use warnings;
use DBI;
use Cwd qw(cwd);
use Fcntl qw(:flock);

use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::SMTPS;
use Email::Simple ();
use Email::Simple::Creator ();
use Text::Table::Tiny;


my $log_to_file ; 
my $print_to_stdout; 
my $log_dir;
my $pub_dir;
my $workdir = cwd;

########## Configuration #######################################
my $out_bytes_threshold = -500000; # if this outbound bytecount is exceeded AND there is more outbound bytes than inbound bytes, we'll send an email alert (this number requires LOTS of tuning to get right)
# my $querylimiter = 500; # Limits the number of Destination Ip Addresses to Process for each Query, Every 15 Minutes 
$log_dir = $workdir . "/logs/"; #path to log dir default is .+log
$pub_dir = $workdir . "/public/reports/"; #path to log dir default is .+log
$log_to_file = "ON";            # OFF or ON
$print_to_stdout = "ON";        # OFF or ON
my $username = "rick";  # database server username
my $password = '2!sTurKs';  # database server password
my $smtpserver   = 'smtpserver.com';        # email server SMTP Server
my $smtpport     = 465;                               # smtp port 
my $smtpuser     = 'originator@yourdomain.com';  # smtp username
my $smtppassword = 'M5UOS23cF21y2w3pzqi';              # smtp password
my $email_to_address = 'recipient@yourdomain.com';       # email receivers address
my $email_from_address = 'originator@yourdomain.com';  # report senders email address
################################################################

while (1) {
    
    eval {
    my $nowtime = localtime;
    print "\n\n--#######################--\n";
    print "Starting new Deltabytes Session... \n";
    std_log_evt("$nowtime - Starting new DeltaBytes Session... ");
 ###################################
 
   
    # Database vars
    my $dsn = "DBI:mysql:socketdb";
    my %attr = (PrintError=>0,RaiseError=>1 );
    
    # connect to database
    std_log_evt("Connecting to Database Server...\n");
    my $dbh = DBI->connect( $dsn, $username, $password, \%attr );
    
    my $tmp_int_host = "";
    my $tmp_dest_ip = "";
    my $tmp_dest_netname = "";
    my @allevents;
    my @anon = ("IntHost","RemoteHost","NetworkName","InBytes","OutBytes","DeltaBytes");
    push @allevents, \@anon;
    my $ctr; 
    ###################################################
    
    
      print "Starting Inbound Outbound Delta byte Count Check for Last 2 Hours... \n";
     
     # Fetch List of Int Hostnames that we will use for future searching 
     
     my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');

     $sth->execute(); 
   
     my $inthosts = $sth->fetchall_arrayref;
     
     $sth->finish;
     
     
     
     # Now For each Internal Host Lets fetch DST IPs for the last 2 hours
    
     foreach my $int_host (@$inthosts) {
    
            # next if ($int_host->[1] eq '');
             
             $tmp_int_host = $int_host->[1];
             
            print "Processing Host: $tmp_int_host and $int_host->[1] For Delta Bytes Activity Last Two Hours... \n ";
            
    
            $sth = $dbh->prepare('SELECT distinct DstIp, NetName FROM socketdb.tabel1 where SrcIpHostname = ? AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 2 HOUR) limit 500;');
           
             $sth->execute($int_host->[1]);


           # pull in array ref of dest Ips to work through
           
             my $dstiplist = $sth->fetchall_arrayref;

             $sth->finish;
             
         # Now Lets examine inbound and outbound byte counts for the last 2 hours to determine if outbound bytes were greater than inbound bytes - send alert email if true 
             
              foreach my $dst_address (@$dstiplist) {
               
                         next if ($dst_address->[0] eq '');               
               
                      $tmp_dest_ip = $dst_address->[0];
                      $tmp_dest_netname = $dst_address->[1];
                      
                 print "Querying Dest: $tmp_dest_ip Net: $tmp_dest_netname  For Connections to Int Host: $tmp_int_host Last Two Hours... \n ";           
               
               
                         $sth = $dbh->prepare('Select sum(BytesInCount - BytesOutCount) as DeltaBytes, BytesInCount, BytesOutCount  from 
                        (SELECT sum(Bytes) as BytesInCount FROM socketdb.tabel1 where tabel1.DstIpHostname = ? AND tabel1.SrcIp = ? and tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 4 HOUR)) as BytesIn,
                        (SELECT sum(Bytes) as BytesOutCount FROM socketdb.tabel1 where tabel1.SrcIpHostname = ? AND tabel1.DstIp = ? and tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 4 HOUR)) as BytesOut');
                           
                        $sth->execute($tmp_int_host ,$tmp_dest_ip,$tmp_int_host,$tmp_dest_ip);

                        
                        
                               while ( my $row = $sth->fetchrow_hashref() ) {
                                
                                # If Deltabytes is <1 Then It should be flagged as Potentially Malicious as Outbound Bytes Exceeds Inbound Bytes
                                
                                my $deltabytes = $row->{DeltaBytes};
                                
                                if ($deltabytes == '') { $deltabytes = 0;}
                                
                                my $bytesincount = $row->{BytesInCount};
                                if ($bytesincount == '') { $bytesincount = 0;}
                                
                                my $bytesoutcount   = $row->{BytesOutCount};
                                if ($bytesoutcount == '') { $bytesoutcount = 0;}
                                
                                my $convertedbytes = ($deltabytes / (1024 * 1024));
                                 $convertedbytes = sprintf("%.2f", $convertedbytes);
                                my $finalbytes = "$deltabytes ($convertedbytes MB)";
                                
                                print "Fetched Delta: $deltabytes BytesIn: $bytesincount, BytesOut: $bytesoutcount - DeltaBytes: $finalbytes \n ";
                                
                                     if ($deltabytes < $out_bytes_threshold) {
                                      $ctr++;
                                         print "\n\n SENDING ALERT!!! Outbound::Inbound Bytes Threshold Exceeded for Communicant Pair: $tmp_int_host <-> $tmp_dest_ip $tmp_dest_netname \n\n";
                                          my @anon = ("$tmp_int_host","$tmp_dest_ip","$tmp_dest_netname","$bytesincount","$bytesoutcount","$finalbytes");
                                          push @allevents, \@anon;
                                      
                                     } else {
                                      
                                     print "Okay, Normal Outbound::Inbound Byte Count exchanged between Source Dest Pair: $tmp_int_host <-> $tmp_dest_ip $tmp_dest_netname\n";                           
                                      
                                     }

                              }
                        $sth->finish;                        
         }
              
  }
     
    if ($ctr) {
         my $nowtime = localtime;
         std_log_evt("$nowtime - $ctr Events found during this session, starting to sending alert email...\n");
         send_email(@allevents);
        
    }
    else {
        my $nowtime = localtime;
        std_log_evt("$nowtime - No events detected exceeding preset threshold, cannot send email...\n");
    }
    
    
    ###################################################
    
             # Loop Complete, lets wait for a few minutes before restarting
           std_log_evt("... sleeping...");

           
           
           $| =1;
           my $sleeper = 1800; # Sleep for 1800 seconds (30 minutes) before restarting

            print "DeltaBytes Watcher sleeping for 30 minutes (1800 seconds)...";
           while ($sleeper > 1) {
                 $sleeper = $sleeper - 1;
                 print ".";
                 sleep(1);
           }
           $| = 0;
 
 
    }; # end of eval

}



sub send_email {
 
 
    my (@allevents) = @_;

    my $email_body_header = "\n\n Delta Bytes Report: Destinations Where Outbound Bytes Exchanged Exceeded Inbound Bytes Last 2 Hours AND Outbound Bytes where Greater than $out_bytes_threshold Bytes Threshold \n\n";
    
    
    my $rows = \@allevents;
    
     my $table_var = Text::Table::Tiny::table(rows => $rows, separate_rows => 1, header_row => 1);
    
    my $nowtime = localtime;

    std_log_evt("Starting Email Connection\n");

    std_log_evt("Building Email Transport\n");
     
     my $transport = Email::Sender::Transport::SMTPS->new({
      host => $smtpserver,
      ssl => 'ssl',
      port => $smtpport,
      sasl_username => $smtpuser,
      sasl_password => $smtppassword,
      debug => 1,
    });
    
    std_log_evt("Creating Email Content\n");
    my $email = Email::Simple->create(
      header => [
        To      => "$email_to_address",
        From    => "$email_from_address",
        Subject => "$nowtime - DeltaBytes Traffic Threshold Alert Message ",
      ],
      body => "$nowtime Destinations Where Outbound Bytes Communicated Exceeded Inbound Bytes Last 2 Hours Alert Message \n $email_body_header \n\n $table_var \n\n",
    );

    std_log_evt("Sending Email\n");
     sendmail($email, { transport => $transport });
    
    std_log_evt("Email Send Complete!\n");
    
    store_report("$nowtime Destinations Where Outbound Bytes Communicated Exceeded Inbound Bytes Last 2 Hours \n $email_body_header \n\n $table_var \n\n");
 
}






sub store_report {

    my ($invar) = @_;

    my ( $DAY, $MONTH, $YEAR ) = (localtime)[ 3, 4, 5 ];
    $YEAR  = $YEAR + 1900;
    $MONTH = $MONTH + 1;

    if ( $MONTH < 10 ) { $MONTH = "0" . "$MONTH"; }
    if ( $DAY < 10 )   { $DAY   = "0" . "$DAY"; }
    my $FQDTG = "$YEAR$MONTH$DAY";

    my $logfile = "$pub_dir" . "Daily_Reports_For_";
    $logfile .= "$FQDTG";
    $logfile .= ".txt";
                
        open my $DB, '>>', $logfile  || warn "Error Opening Current Reports File $logfile \n";
        
        flock $DB, LOCK_EX;
        print $DB "$invar \n";
        close $DB;
 
}



sub std_log_evt {

    my ($invar) = @_;
    chomp($invar);
    my ( $DAY, $MONTH, $YEAR ) = (localtime)[ 3, 4, 5 ];
    $YEAR  = $YEAR + 1900;
    $MONTH = $MONTH + 1;

    if ( $MONTH < 10 ) { $MONTH = "0" . "$MONTH"; }
    if ( $DAY < 10 )   { $DAY   = "0" . "$DAY"; }
    my $FQDTG = "$YEAR$MONTH$DAY";

    my $logfile = "$log_dir" . "SocketSurveyer_Daily_DeltaBytes_Log";
    $logfile .= "$FQDTG";
    $logfile .= ".txt";

  if ($log_to_file eq "ON") {
      
        open my $DB, '>>', $logfile  || warn "Error Opening Current Logfile $logfile \n";
        
        flock $DB, LOCK_EX;
        print $DB "$invar \n";
        close $DB;
        
        if ($print_to_stdout eq "ON") {
            print "$invar \n";   
        }

        
    } elsif ($log_to_file eq "OFF") {
        if ($print_to_stdout eq "ON") {
            print "$invar \n";   
        }

        
    }

    

}


