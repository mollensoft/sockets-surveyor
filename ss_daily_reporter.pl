#
# SocketsSurveyor Daily Reporter Daemon V1
# Basic Way to query Database for interesting events and correlations and then email them out to a distribution for situational awareness or further analysis
#
# MIT License Copyright (c) [2018] [Mark Mollenkopf]
#


use strict;
use warnings;
use DBI;
use Cwd qw(cwd);
use Fcntl qw(:flock);
use Net::Telnet::Gearman;
use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::SMTPS;
use Email::Simple ();
use Email::Simple::Creator ();
use Text::Table::Tiny;
use DateTime;

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
my $username = 'rick';  # database server username
my $password = '2!sTurKs';  # database server password
my $smtpserver   = 'smtpserver.com';        # email server SMTP Server
my $smtpport     = 465;                               # smtp port 
my $smtpuser     = 'originator@yourdomain.com';  # smtp username
my $smtppassword = 'M5UOS23cF21y2w3pzqi';              # smtp password
my $email_to_address = 'recipient@yourdomain.com';        # email receivers address
my $email_from_address = 'originator@yourdomain.com';  # report senders email address

################################################################

while (1) {
    
      eval { # using eval to trap quirky issues with Text::Table::Tiny
       
    my $nowtime = localtime;
    print "\n\n--#######################--\n";
    print "Starting new Session... \n";
    std_log_evt("$nowtime - Starting new Session... ");
 ###################################
 
     my @allevents;
     my $events_str;
     
    # Database vars
    my $dsn = "DBI:mysql:socketdb";

    my %attr = (PrintError=>0,RaiseError=>1 );
    
    # connect to database
    std_log_evt("Connecting to Database Server...\n");

    my $dbh = DBI->connect( $dsn, $username, $password, \%attr );
    
    my $sth = $dbh->prepare( "SELECT count(*) FROM socketdb.DistinctDests where stamp_created >= DATE_SUB(NOW(), INTERVAL 24 HOUR);");

    $sth->execute();

    my ($distinct_count) = $dbh->selectrow_array($sth);
    
    std_log_evt("Received 1... $distinct_count\n");
    
    $distinct_count = "1. Distinct Destinations Added Last 24 Hours: [" . $distinct_count . "] "; 
 
     $sth->finish;
     
     ####################################################################

     $sth = $dbh->prepare( "SELECT count(*) FROM socketdb.DistinctDests;");

    $sth->execute();

    my ($distinct_total_count) = $dbh->selectrow_array($sth);
    
    std_log_evt("Received 5... $distinct_total_count\n");
        
     $distinct_count .= " Of [$distinct_total_count] Total Distinct Destinations\n";

    push @allevents, $distinct_count;     
    
    $sth->finish; 
    ################################################################

    
    ####################################################################

     $sth = $dbh->prepare( "SELECT count(*) FROM socketdb.tabel1 where stamp_created >= DATE_SUB(NOW(), INTERVAL 24 HOUR);");

    $sth->execute();

    my ($events_24count) = $dbh->selectrow_array($sth);
    
    std_log_evt("Received 2... $events_24count\n");    

    $events_24count = "2. Total New Events Occurring in Last 24 Hours: [" . $events_24count . "] \n";     
    
    push @allevents, $events_24count;    

         $sth->finish;
  # update all   
    ################################################################

    ####################################################################

     $sth = $dbh->prepare( "SELECT count(*) FROM socketdb.tabel1;");

    $sth->execute();

    my ($events_total_count) = $dbh->selectrow_array($sth);
    
    std_log_evt("Received 3... $events_total_count\n");      

     $events_total_count = "3. Total Events in Events Table: [" . $events_total_count . "] \n"; 
     
    push @allevents, $events_total_count;
    
    $sth->finish;
         
     
    ################################################################
    
    ####################################################################

     $sth = $dbh->prepare( "SELECT count(*) FROM socketdb.DistinctDests where reputation = 3 and stamp_created >= DATE_SUB(NOW(), INTERVAL 24 HOUR);");

    $sth->execute();

    my ($distinct_rep3_count) = $dbh->selectrow_array($sth);
    
    std_log_evt("Received 4... $distinct_rep3_count\n");
    
    $distinct_rep3_count = "4. Total Reputation 3 Events Occurring Last 24 Hours: [" . $distinct_rep3_count . "] \n"; 

    push @allevents, $distinct_rep3_count;     
    
    $sth->finish; 
    ################################################################
      my $wstats = fetch_workerstats();
      
      my $repstats = checkstat_ReputationWorker();
      
      my $flowstat = checkstat_rflowRcvr();
      
      my $gmandstat =  checkstat_gearmand();
     
      my $dailyrptstat =  checkstat_dailyreporter();
     
      push @allevents, "5. Reputation Worker Status: [$repstats]\n";
      push @allevents, "6. Flow Receiver Status: [$flowstat]\n";
      push @allevents, "7. Daily Reporter Worker Status: [$dailyrptstat]\n";        
      push @allevents, "8. Gearmand Status: [$gmandstat]\n";
      push @allevents, "9. Event Worker Status: $wstats\n";
   
    ################################################################
  
    
     ####################################################################

     $sth = $dbh->prepare( "SELECT stamp_created, count(*) as counter FROM socketdb.tabel1  where tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 168 HOUR) GROUP BY hour( stamp_created ) , day( stamp_created )  order by stamp_created asc;;");

    $sth->execute();
  
    my $dtg;
    my $count;
    my $ctr;
    my @rowfiller;
  
  while ( my $row = $sth->fetchrow_hashref() ) {
    
       $ctr++;
       $dtg = $row->{stamp_created};
       $count = $row->{counter};
       
       $dtg =~ s/://g;
       
       chop($dtg);
       chop($dtg);
       chop($dtg);
       chop($dtg);
       
       push @rowfiller, "$dtg - $count";
  
  }
    std_log_evt("Received 6... @rowfiller\n");
    
    my $varsynch =  join("\n", @rowfiller), "\n";

    push @allevents, "\nTotal Events Per Hour, Last 7 Days: \n\n";       
    
    push @allevents, $varsynch;     
    
    $sth->finish; 
    
   
    send_email(@allevents);
 
 ################################################
 
     std_log_evt("Starting OffHours Traffic Report\n");
     my $dt   = DateTime->now;
     my $date = $dt->ymd;
     my $date1 = "$date 05:00:00";  # Start of Off Hours Date Time ( the day and hours when no one is using devices and traffic should be slow , typically midnight to 6AM with a -4 hour offset for me at EST time)
     my $date2 = "$date 10:00:00";  # End Off Hours date time
     
     $dbh = DBI->connect( $dsn, $username, $password, \%attr );
    
     $sth = $dbh->prepare( "SELECT DstIp, DstIpHostname, DstIpOrg, count(*) as counter, sum(Bytes) as Bytecount  FROM socketdb.tabel1 where srcIp like '192.168%' and stamp_created between
                            ? and ? group by DstIp order by counter desc limit 10000 ;" );
     
     std_log_evt("Executing query using $date1 and $date2\n");
     
     $sth->execute($date1,$date2); 
    
     my @allevents2;
     my @anon2 = ("DstIp","DstIpHostname","DstIpOrg","Count","Bytes");
     push @allevents2, \@anon2;            
            
 while ( my $row = $sth->fetchrow_hashref() ) {
        
        my $DstIp =  $row->{DstIp};
        my $DstIpHostname       = $row->{DstIpHostname};
        $DstIpHostname =~ s/\v//g;
        my $DstIpOrg = $row->{DstIpOrg};
        $DstIpOrg =~ s/\v//g;
        my $counter     = $row->{counter};
        my $Bytes   = $row->{Bytecount};
        
        my @anon2 = ("$DstIp","$DstIpHostname","$DstIpOrg","$counter","$Bytes");
        push @allevents2, \@anon2;

    }
     $sth->finish();

     std_log_evt("Sending Traffic Report Email...");
     send_email_traffic_rpt(@allevents2);
################################################

    
    my @allevents3;
    
   $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
     
     $sth->execute(); 
    
        my @anon = ("Internal Host","Total Count","Count Distinct Dests", "Count Distinct Orgs","Count Distinct Dest Ports", "Bytes");
        
        push @allevents3, \@anon;            
    
  my $rows3 = $sth->fetchall_arrayref;

  foreach my $item (@$rows3) {
    
       next if ($item->[1] eq '');


      $sth = $dbh->prepare('SELECT  SrcIpHostname, count(*) as TotalCount, count(distinct DstIp) as CountDistDests,
                           count(distinct DstIpOrg) as CountDistOrgs, count(distinct DstPort) as CountDistDestPorts,
                           sum(Bytes) as TotalBytes FROM socketdb.tabel1 where SrcIpHostname = ? AND stamp_created >=
                           DATE_SUB(NOW(), INTERVAL 24 HOUR) ;');
        
      $sth->execute($item->[1]);
      
         my $ctr;
         
 while ( my $row = $sth->fetchrow_hashref() ) {
        
        my $SrcIpHostname = $row->{SrcIpHostname};
                
        next if ($SrcIpHostname eq '');
 
        my $TotalCount = $row->{TotalCount};
        my $CountDistDests     = $row->{CountDistDests};
        my $CountDistOrgs   = $row->{CountDistOrgs};
        my $CountDistDestPorts  = $row->{CountDistDestPorts};
        my $TotalBytes      = $row->{TotalBytes};

        my @anon = ("$SrcIpHostname","$TotalCount","$CountDistDests","$CountDistOrgs","$CountDistDestPorts","$TotalBytes");
        push @allevents3, \@anon;
        $ctr++;

      }

  }

     $sth->finish();
      send_email_sumEvent_rpt(@allevents3);
    
    
    ######################
    
    ######################
   
   print "Starting Internal Host Daily Report\n";
    
    my @allevents4;
    
     $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');

     $sth->execute(); 
    
        my @anon = ("Internal Host","Rep","DST IP", "Evts","Bytes", "DST Hostname", "DST Org", "NETName","First Seen", "Last Seen", "Timespan");

        my $daycounts = "\n------------------------------------\n";
        
        my $inhost =  "IntHost";
        my $counthst =  "Count";
        my $byteshst = "Bytes Last 24 Hrs";
        my $humanreadbytes = "In MegaBytes";
         
        $daycounts .= sprintf("%-15s %-10s %-10s %-10s\n", $inhost, $counthst, $byteshst, $humanreadbytes);
                
        
        push @allevents4, \@anon;            
         
        my $rows3 = $sth->fetchall_arrayref;
  
      
    
    ##############
      foreach my $item (@$rows3) {
    
             next if ($item->[1] eq '');
       
            $sth = $dbh->prepare('SELECT SrcIpHostname, count(*) as counter, sum(Bytes) as bytes FROM
                                 socketdb.tabel1 where SrcIpHostname = ? AND stamp_created >= DATE_SUB(NOW(), INTERVAL 24 HOUR)');
        
      $sth->execute($item->[1]);
      

         
 while ( my $row = $sth->fetchrow_hashref() ) {
        
        my $SrcIpHostname = $row->{SrcIpHostname};
                
                print "print srchost: $SrcIpHostname \n";
                
        next if ($SrcIpHostname eq '');
 
        my $daycounter = $row->{counter};
        my $daybytes   = $row->{bytes};
        
        my $convertedbytes = ($daybytes / (1024 * 1024));
         $convertedbytes = sprintf("%.2f", $convertedbytes);
        my $finalbytes = "$convertedbytes MB";
        print "Fetched: $SrcIpHostname - $daycounter,$daybytes,$convertedbytes \n ";

        $daycounts .= sprintf("%-15s %-10s %-10s %-10s\n", $SrcIpHostname, $daycounter, $daybytes, $finalbytes);
        
      }
    
  }
     ################

  foreach my $item (@$rows3) {
    
       next if ($item->[1] eq '');
       
       print "processing item: $item->[1] \n\n";


      $sth = $dbh->prepare('SELECT tabel1.SrcIpHostname, DistinctDests.Reputation, tabel1.DstIp, count(*) as Counter, sum(tabel1.Bytes) as bytecount,
                           tabel1.DstIpHostname, tabel1.DstIpOrg, tabel1.NetName FROM socketdb.tabel1 INNER JOIN DistinctDests On tabel1.DstIp = DistinctDests.DstIp
                           where SrcIpHostname = ? AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 24 HOUR) group by tabel1.DstIp order by Counter desc limit 500;');
        
      $sth->execute($item->[1]);
      
         my $ctr;
         
       while ( my $row = $sth->fetchrow_hashref() ) {
        
        my $SrcIpHostname = $row->{SrcIpHostname};
                
                print "print srchost: $SrcIpHostname \n";
                
        next if ($SrcIpHostname eq '');
 
        my $reptuation = $row->{Reputation};
        my $dstip     = $row->{DstIp};
        
        ####################################
        # Fetching First and Last Seen and Span
        
        my $sth2 = $dbh->prepare('SELECT stamp_created FROM socketdb.tabel1 where DstIp = ? order by uid desc limit 1;');
                    
        $sth2->execute($dstip);
                    
        my $lastseen = $sth2->fetchrow_array(); 

        
        
        $sth2 = $dbh->prepare('SELECT stamp_created FROM socketdb.tabel1 where DstIp = ? order by uid asc limit 1');
                    
        $sth2->execute($dstip);
                    
        my $firstseen = $sth2->fetchrow_array(); 
 
        
        $sth2 = $dbh->prepare('SELECT TIMESTAMPDIFF(DAY, ?,?)');
        $sth2->execute($firstseen, $lastseen);
        my $spandays = $sth2->fetchrow_array(); 

        $sth2 = $dbh->prepare('SELECT TIMESTAMPDIFF(HOUR, ?,?)');
        $sth2->execute($firstseen, $lastseen);
        my $spanhours = $sth2->fetchrow_array();
        
        my $span_time = $spandays .  " Days (" . $spanhours . " Hours)";  
        
        ####################################
        
        my $count   = $row->{Counter};
        
        my $TotalBytes      = $row->{bytecount};
        my $dstHostname  = $row->{DstIpHostname};

        my $dstIpOrg   = $row->{DstIpOrg};
        my $netName      = $row->{NetName};
        my $surveyrslts  = $row->{SurveyRslts};        
        
        print "Fetched:  $SrcIpHostname,$reptuation,$dstip,$count,$TotalBytes,$dstHostname,$dstIpOrg,$netName,, $firstseen,, $lastseen,, $span_time  \n ";
  
        my @anon = ("$SrcIpHostname","$reptuation","$dstip","$count","$TotalBytes","$dstHostname","$dstIpOrg","$netName",$firstseen,$lastseen,$span_time);
        push @allevents4, \@anon;
        $ctr++;

      }

  }

     $sth->finish();
     $dbh->disconnect();
       send_email_DeviceEvent_rpt($daycounts, @allevents4);
      
    ######################

    
    ######################     


    
            # Loop Complete, lets wait for a few minutes before restarting
           std_log_evt("... sleeping...");
           
           
           $| =1;
           my $sleeper = 43200;
           #my $sleeper = 43200; # Half a day
            print "sleeping for 12 Hours (43200 seconds)...";
           while ($sleeper > 1) {
                 $sleeper = $sleeper - 1;
                 print ".";
                 sleep(1);
           }
           $| = 0;
 
 
   }; # end of eval

}



sub send_email {
 
 
    my (@allevents, @rowfiller) = @_;

    my $email_body_payload  = join '\n', @allevents;    
    my $nowtime = localtime;
    my $email_body_header = "SocketsSurveyor Daily Report - $nowtime \n\n";

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
        Subject => "SocketsSurveyor Daily Report - $nowtime ",
      ],
      body => "SocketsSurveyor Daily Report $nowtime \n----------------\n @allevents \n",
    );
    
    std_log_evt("Sending Email\n");
    sendmail($email, { transport => $transport });
     
    std_log_evt("Email Send Complete!\n");
    
    store_report("SocketsSurveyor Daily Report $nowtime \n----------------\n @allevents \n");
 
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

    my $logfile = "$log_dir" . "SocketSurveyer_Reporter_Worker_Std_Log";
    $logfile .= "$FQDTG";
    $logfile .= ".txt";

  if ($log_to_file eq "ON") {
       
         open my $DB, '>>', $logfile  || warn "Error Opening Current Reports File $logfile \n";
        
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







sub fetch_workerstats {
  my $n = shift;
      my $session = Net::Telnet::Gearman->new(
        Host => '127.0.0.1',
        Port => 4730,
    );
    my @status   = $session->status();
    my @workers   = $session->workers();
    my $version   = $session->version();
    my $statstr = "GearmanD Version: $version \nWorker Status: \n" ; 
    
    foreach my $sitem (@status) {
   
    $statstr .= "Name: $sitem->{name} ";
    $statstr .= " Running: $sitem->{running} ";
    $statstr .= " Busy: $sitem->{busy} " ;
    $statstr .= " Free: $sitem->{free} ";
    $statstr .= " Queue: $sitem->{queue}\n";
    
}

    
    my $workers = "$statstr";
    
    foreach my $item (@workers) {
        $workers .= "Worker: ";
        $workers .= $item->{ip_address};
        $workers .= " - ";
        $workers .= $item->{client_id};
        $workers .= " - ";
        $workers .= $item->{functions}[0];
        $workers .= "\n";
    }
  
 return $workers 
}

sub checkstat_ReputationWorker {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_gearman_reputation_worker.pl" | grep -v grep | wc -l`;
  if ($shellval == 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}

sub checkstat_rflowRcvr {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_Rflow_rcvrd.pl" | grep -v grep | wc -l`;
  if ($shellval == 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}

sub checkstat_gearmand {
  my $n = shift;
  my $retval;
  my $shellval = `ps cax | grep gearmand`;
  if ($shellval) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}

sub checkstat_dailyreporter {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_daily_reporter.pl" | grep -v grep | wc -l`;
  if ($shellval == 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}



sub send_email_sumEvent_rpt {
 
 
    my (@allevents) = @_;

    my $email_body_header = "\nDevice Event Traffic Summary Last 24 hours:\n\n";
    
    my $rows = \@allevents;
    
     my $table_var = Text::Table::Tiny::table(rows => $rows, separate_rows => 1, header_row => 1);

    my $nowtime = localtime;
     
     my $transport = Email::Sender::Transport::SMTPS->new({
      host => $smtpserver,
      ssl => 'ssl',
      port => $smtpport,
      sasl_username => $smtpuser,
      sasl_password => $smtppassword,
      debug => 1,
    });
    
    my $email = Email::Simple->create(
      header => [
        To      => "$email_to_address",
        From    => "$email_from_address",
        Subject => "$nowtime Summary All Devices Network Activity Last 24 hours",
      ],
      body => "$nowtime Summary Event Traffic Report  \n $email_body_header \n\n $table_var \n\n",
    );


     sendmail($email, { transport => $transport });
     
     store_report("$nowtime Summary Event Traffic Report  \n $email_body_header \n\n $table_var \n\n");
        
        
}








      
sub send_email_DeviceEvent_rpt {
 
 
    my ($daycounts, @allevents) = @_;

    my $email_body_header = "\nDaily Internal Device Report:\n\n";
    
    my $rows = \@allevents;
    
     my $table_var = Text::Table::Tiny::table(rows => $rows, separate_rows => 1, header_row => 1);
     
    my $nowtime = localtime;
     
     my $transport = Email::Sender::Transport::SMTPS->new({
      host => $smtpserver,
      ssl => 'ssl',
      port => $smtpport,
      sasl_username => $smtpuser,
      sasl_password => $smtppassword,
      debug => 1,
    });
    
    my $email = Email::Simple->create(
      header => [
        To      => "$email_to_address",
        From    => "$email_from_address",
        Subject => "$nowtime Daily Internal Device Report",
      ],
      body => "$nowtime - Total Event/Byte Counts Per Internal Device and Top 500 Destinations Grouped by Each Internal Device Last 24 Hours \n\n $daycounts \n\n------------------------------------\n\n $table_var \n\n",
    );


     sendmail($email, { transport => $transport });
     
    store_report("$nowtime - Total Event/Byte Counts Per Internal Device and Top 500 Destinations Grouped by Each Internal Device Last 24 Hours \n\n $daycounts \n\n------------------------------------\n\n $table_var \n\n");
        
        
}







   
sub send_email_traffic_rpt {
 
 
    my (@allevents) = @_;

    my $email_body_header = "\nDaily Down-Hours Traffic Report (0100L-0600L) - All Devices:\n\n";
    
    my $rows = \@allevents;
    
     my $table_var = Text::Table::Tiny::table(rows => $rows, separate_rows => 1, header_row => 1);

    my $nowtime = localtime;

     my $transport = Email::Sender::Transport::SMTPS->new({
      host => $smtpserver,
      ssl => 'ssl',
      port => $smtpport,
      sasl_username => $smtpuser,
      sasl_password => $smtppassword,
      debug => 1,
    });
    
    my $email = Email::Simple->create(
      header => [
        To      => "$email_to_address",
        From    => "$email_from_address",
        Subject => "$nowtime Daily Down-Hours Traffic Report (0100L-0600L) - All Devices:",
      ],
      body => "$nowtime Daily Down-Hours Traffic Report  \n $email_body_header \n\n $table_var \n\n",
    );

     sendmail($email, { transport => $transport });
    
   store_report("$nowtime Daily Down-Hours Traffic Report  \n $email_body_header \n\n $table_var \n\n");

 
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
