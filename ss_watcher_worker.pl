#
# SocketsSurveyor Alerter Daemon V1
#
# Performs SQL Queries looking for Outbound Size thresholds to be met and sends Email Alert
#
# This is the future home of other alerting query/response actions
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
$log_dir = $workdir . "/logs/"; #path to log dir default is .+log
$pub_dir = $workdir . "/public/reports/"; #path to log dir default is .+log
$log_to_file = "ON";            # OFF or ON
$print_to_stdout = "ON";        # OFF or ON
my $username = "rick";  # database server username
my $password = '2!sTurKs';  # database server password
my $smtpserver   = 'smtpserver.com';        # email server SMTP Server
my $smtpport     = 465;                               # smtp port 
my $smtpuser     = 'originator@yourdomain.com';  # smtp username
my $smtppassword = 'wUOS2NcF2By2w3pz1i';              # smtp password
my $email_to_address = 'recipient@yourdomain.com';       # email receivers address
my $email_from_address = 'originator@yourdomain.com';  # report sender script (this script) email address to send from
################################################################

while (1) {
    
    eval { # trap a quirky issue with text table
    my $nowtime = localtime;
    print "\n\n--#######################--\n";
    print "Starting new Session... \n";
    std_log_evt("$nowtime - Starting new Session... ");
 ###################################
 
   
    # Database vars
    my $dsn = "DBI:mysql:socketdb";
    my %attr = (PrintError=>0,RaiseError=>1 );
    
    # connect to database
    std_log_evt("Connecting to Database Server...\n");
    my $dbh = DBI->connect( $dsn, $username, $password, \%attr );
    
  
     my $sth = $dbh->prepare( "SELECT stamp_created, SrcIpHostname, DstIp, DstIpHostname, DstIpOrg, Packets, Bytes, Proto, DstPort FROM socketdb.tabel1 where SrcIp like '192.168%' AND bytes >= 1000000 AND stamp_created >= DATE_SUB(NOW(), INTERVAL 10 minute) order by stamp_created desc limit 10000;" );
   
       std_log_evt("Performing Sql Query...\n");
       $sth->execute(); 
    
            my $ctr;
            my @allevents;
        my @anon = ("Event DateTime","SrcIpHostname","DstIp","DstIpHostname","DstIpOrg","Packets","Bytes","Proto","DstPort");
        push @allevents, \@anon;            
            
 while ( my $row = $sth->fetchrow_hashref() ) {
        

        my $stamp_created         = $row->{stamp_created};
        my $SrcIpHostname = $row->{SrcIpHostname};
        my $DstIp     = $row->{DstIp};
        my $DstIpHostname   = $row->{DstIpHostname};
        my $DstIpOrg  = $row->{DstIpOrg};
        my $Packets      = $row->{Packets};
        my $Bytes      = $row->{Bytes};
        my $Proto   = $row->{Proto};
        my $DstPort   = $row->{DstPort};
        
        my @anon = ("$stamp_created","$SrcIpHostname","$DstIp","$DstIpHostname","$DstIpOrg","$Packets","$Bytes","$Proto","$DstPort");
        push @allevents, \@anon;
        $ctr++;

    }
 
 
    
     $sth->finish();
     $dbh->disconnect();
 
    if ($ctr) {
         my $nowtime = localtime;
         std_log_evt("$nowtime - $ctr Events found during this session, starting to sending alert email...\n");
         send_email(@allevents);
        
    }
    else {
        my $nowtime = localtime;
        std_log_evt("$nowtime - No events detected during query, cant send email...\n");
    }

             # Loop Complete, lets wait for a few minutes before restarting
           std_log_evt("... sleeping...");

           
           
           $| =1;
           my $sleeper = 602;
           #my $sleeper = 271;
            print "sleeping for 10 minutes (600 seconds)...";
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

    my $email_body_header = "\nOutbound Events occurring in the last 10 Minutes where outbound Bytes >= 1 MBs \n\n";
    
    
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
        Subject => "$nowtime - Outbound Traffic Threshold Alert Message ",
      ],
      body => "$nowtime SocketsSurveyor Outbound Traffic Alert Message \n $email_body_header \n\n $table_var \n\n",
    );

    std_log_evt("Sending Email\n");
     sendmail($email, { transport => $transport });
    
    std_log_evt("Email Send Complete!\n");
    
    store_report("$nowtime SocketsSurveyor Outbound Traffic Alert Message \n $email_body_header \n\n $table_var \n\n");
 
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

    my $logfile = "$log_dir" . "SocketSurveyer_Watcher_Worker_Std_Log";
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



