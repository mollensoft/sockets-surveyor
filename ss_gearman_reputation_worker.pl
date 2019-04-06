#
# SocketsSurveyor Reputation Daemon V1
#
# A very simple processor to fetch reputation data about an IP address
# Requires you to have your own, free, Virustotal API Key as these attributes contribute to the overall reputation calculation
# Planning to add other enrichment mechanisms later from other Service providers (Shodan, AlienVault OTX, etc)
#
# This is also where future IP address survey activity will occur 
#
# MIT License Copyright (c) [2018] [Mark Mollenkopf]
#


use strict;
use warnings;
use LWP::UserAgent;
use JSON;
use Data::Dumper qw(Dumper);
use DBI;
use Cwd qw(cwd);
use Fcntl qw(:flock);

my $log_to_file ; 
my $print_to_stdout; 
my $log_dir;
my $workdir = cwd;

########## Configuration #######################################
$log_dir = $workdir . "/logs/"; #path to log dir default is .+log
$log_to_file = "ON";            # OFF or ON
$print_to_stdout = "ON";        # OFF or ON
my $username = "rick";  # database server username
my $password = '2!sTurKs';  # database server password
my $virustotal_api_key = 'c457f10a95e43a11b882544690cfc1564c495d7047bab7bf3672c7c1fc8f0ca7'; # This is your API Key from Virus total, needed to lookup Reputation data per IP address (this one is not real) 
################################################################


while (1) {
    
    eval { # stop unexpected error condition from stopping process
    
    print "\n\n--#######################--\n";
    print "Starting new Session... \n";
    std_log_evt("Starting new Session... ");
 ###################################
 
   
    # Database vars
    my $dsn = "DBI:mysql:socketdb";

    my %attr = (PrintError=>0,RaiseError=>1 );
    
    # connect to MySQL database
    my $dbh = DBI->connect($dsn,$username,$password,\%attr);
    
    my $sth = $dbh->prepare( "SELECT DstIp FROM socketdb.DistinctDests where Reputation is NULL order by stamp_created desc limit 1;" );
    $sth->execute();
    my ($ip2check) = $sth->fetchrow_array(); 
   
    $sth->finish();

    $dbh->disconnect(); 
    print "Got IP: $ip2check from db Query... checking reputation for IP Address: $ip2check \n";
    std_log_evt("Got IP: $ip2check from db Query ... checking reputation for IP Address: $ip2check");
    
   ###################################
 
 if ($ip2check) {
    #okay there is an IP to check
            
        my $ua = LWP::UserAgent->new();
        
        my $url="https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$virustotal_api_key&ip=$ip2check";
        
        print "URL:$url \n";
        
        my $response = $ua->get( $url);
        
        my $results = $response->content;
        
        my $http_status = $response->status_line();
        
        print "LWP HTTP Status: $http_status\n";
        std_log_evt("LWP HTTP Status: $http_status");
        
        
        if ($http_status = '200') {
            
            print "HTTP Status was 200 OK... Continuing to Process... \n";
            std_log_evt("HTTP Status was 200 OK... Continuing to Process... ");
            
        } elsif ($http_status = '204') {
            
              print "HTTP Status was 204 OK... Slowing down Processing... \n";
              std_log_evt("HTTP Status was 204 OK... Slowing down Processing... ");
              exit 0; #quit for now - add slow down later
              
            
        } elsif ($http_status = '403') {
            
              print "HTTP 403 Received, Credential Error!... STOPPING PROCESSING \n";
              std_log_evt("HTTP 403 Received, Credential Error!... STOPPING PROCESSING");
              exit 0; #quit for now
            
        }
        
        my $json = JSON->new->allow_nonref;
        
        my $decoded_json = $json->decode($results);
        
        my $reputation = 0;
        #############################
        
        my $pos_urls = 0;
        
        if (exists  $decoded_json->{'detected_urls'} ) {
            
             my @detarray1 = @{ $decoded_json->{'detected_urls'} };
             foreach my $f ( @detarray1 ) {
              #print "URL positives" . $f->{"positives"} . "\n";
              $pos_urls = $pos_urls +  $f->{"positives"};
                }
            } else {
            
            $pos_urls = 0;
        
        }
        
        
        
        ############################
        
        #############################
        
        my $pos_downloads = 0;
        
        if (exists $decoded_json->{'detected_downloaded_samples'}) {
            
            print" it exists\n ";
            my @detarray2 = @{ $decoded_json->{'detected_downloaded_samples'} };
            foreach my $f ( @detarray2 ) {
            # print "Download positives" . $f->{"positives"} . "\n";
            $pos_downloads = $pos_downloads +  $f->{"positives"};
        }
            
        } else {
        
            $pos_downloads = 0;
            
        }
        
        
        
        ############################
        
        
        #############################
        
        my $pos_comsamples = 0;
        
        if (exists  $decoded_json->{'detected_communicating_samples'} ) {
            my @detarray3 = @{ $decoded_json->{'detected_communicating_samples'} };
                foreach my $f ( @detarray3 ) {
              $pos_comsamples = $pos_comsamples +  $f->{"positives"};
            }    
        } else {
        
            $pos_comsamples = 0;
            
        }
        
        
        
        ############################
        
        if ($pos_urls > 0) {$reputation++;}
        if ($pos_downloads > 0) {$reputation++;}
        if ($pos_comsamples > 0) {$reputation++;}
        ###########################
        
        
        print "Response_Code From VT: " . $decoded_json->{'response_code'} . " (0 NotExist - 1 Exists) \n";
        print "Positive URL Counts: $pos_urls \n";
        print "Positive Download Counts: $pos_downloads \n";
        print "Positive Communicating Sample Counts:  $pos_comsamples\n";
        print "Total Reputation for IP Address: $ip2check Reputation: $reputation\n";
        
        std_log_evt("Response_Code From VT: " . $decoded_json->{'response_code'} . " (0 NotExist - 1 Exists) \n");
        std_log_evt("Positive URL Counts: $pos_urls \n");
        std_log_evt("Positive Download Counts: $pos_downloads \n");
        std_log_evt("Positive Communicating Sample Counts:  $pos_comsamples\n");
        std_log_evt("Total Reputation for IP Address: $ip2check Reputation: $reputation\n");
        
        ################################
        
          print "Updating Database IP: $ip2check Reputation: $reputation\n";
        
            $dbh = DBI->connect( $dsn, $username, $password, \%attr );
            
            my $sql_update_statement = "UPDATE DistinctDests SET Reputation = ? WHERE DstIP = ?";
        
            $dbh->do($sql_update_statement,undef,$reputation,$ip2check) or die "Cannot Execute Update: $DBI::err , $DBI::errstr";
        
            $dbh->disconnect();
        
        
            
        
                
        ## Lets Run the whois Updater too #
        ## This is designed to catch up Org-less db entries in the distinct Db Table
        ## A result of mis coding in the event worker script
        print "About to Run Whois updater \n";
        who_is_updater();
        #####################################    
        ################################
        
        print "--#######################--\n\n";
        std_log_evt("--#######################--\n");
    
            $| =1;
            my $sleeper = 17;
            print "sleeping for 15 seconds..."; # sleep 15 seconds because Virustotal throttles to 4 lookups per minute
            while ($sleeper > 1) {
                $sleeper = $sleeper - 1;
                print ".";
                sleep(1);
            }
            $| = 0;
    } else {
             print "About to Run Whois updater \n";
        ## Lets Run the whois Updater too #
        ## This is designed to catch up Org-less db entries in the distinct Db Table
        ## A result of mis coding in the event worker script
        who_is_updater();
        #####################################        

          
            # Okay, No IP To Check
           print "There are Currently Zero IPs to Check Reputation for... sleeping... \n";
           std_log_evt("There are Currently Zero IPs to Check Reputation for... sleeping...");
           
                   
           
           $| =1;
           my $sleeper = 32;
           print "sleeping for 30 seconds...";
           while ($sleeper > 1) {
                 $sleeper = $sleeper - 1;
                 print ".";
                 sleep(1);
           }
           $| = 0;
    
    
 }
 
 
    }; # end of eval

}


sub who_is_updater{
 
 
        ################################
        # Okay Now lets check for any Distinct Destinations that do not have at least a valid org name listed and update that row in the db with an org name and Net Name (or for apnic netname and irt)
        
        print "Checking for Org-less Distinct DB Entries... \n";
        
        # Find a row with no Org Listed
        # SELECT * FROM socketdb.DistinctDests where DstIpOrg = '' order by uid desc limit 1;
               my $dsn = "DBI:mysql:socketdb";
               my %attr = (PrintError=>0,RaiseError=>1 );
               
               # connect to MySQL database
               my $dbh = DBI->connect($dsn,$username,$password,\%attr);
               
               #my $sth = $dbh->prepare( "SELECT DstIp FROM socketdb.DistinctDests where Reputation is NULL order by stamp_created desc limit 1;" );
               my $sth = $dbh->prepare( "SELECT DstIp FROM socketdb.DistinctDests where DstIpOrg = '' and NetName is null order by uid desc;" );

               $sth->execute();
               my ($ip2check) = $sth->fetchrow_array(); 
              
               $sth->finish();
           
               $dbh->disconnect(); 
               print "Got IP: $ip2check from db Query... checking Whois for IP Address: $ip2check \n";
               std_log_evt("Got IP: $ip2check from db Query ... checking Whois for IP Address: $ip2check");
               
            if ($ip2check) {
                  #okay there is an IP to check
        
        
                         # Run the IP Query using the perl pwhois command line utility, extract the OrgName, NetName or netname, irt
                                 my $who_OrgName;
                                 my $who_NetName;
                                 my $who_irt;
                                 my $who_netname;
                                 
                                 my @retval;
                                 
                                eval {  @retval = `/usr/bin/whois $ip2check`; }; # this requires whois binary installed on linux host 
                                 
                                 if ($@) {
                                     err_log_evt("ERROR During Commmand Line Whois Looking Up for $ip2check - $@") if $@;
                                     print" ERROR Looking Up ipinfo $@ \n";
                                 }
                                                                   
                                 

                                 
                                 foreach my $line (@retval)  {
                                    
                                    print "Line: $line \n";
                                     
                                                         if ($line =~ /^OrgName/) {
                                                            
                                                                 $line =~ s/OrgName://;
                                                                 $line =~ s/^\s+//;
                                                                 $line =~ s/\s+$//;
                                                                 $who_OrgName = $line;                          
                                                             
                                                         } elsif ($line =~ /^NetName/) {
                                                                                        
                                                                 $line =~ s/NetName://;
                                                                 $line =~ s/^\s+//;
                                                                 $line =~ s/\s+$//;
                                                                 $who_NetName = $line;
                                                                 
                                                         } elsif ($line =~ /^irt/) {
                                                                       
                                                                 $line =~ s/irt://;
                                                                 $line =~ s/^\s+//;
                                                                 $line =~ s/\s+$//;
                                                                 $who_irt = $line;                                
                                                                 
                                                         } elsif ($line =~ /^netname/) {
                                                             
                                                                 $line =~ s/netname://;
                                                                 $line =~ s/^\s+//;
                                                                 $line =~ s/\s+$//;                            
                                                                 $who_netname = $line;                           
                                                             
                                                         }
                                 }
                                  
                                  
                                  if (($who_OrgName) || ($who_NetName)) {
                                     
                                     print "FinalA: $who_OrgName, $who_NetName \n ";
                       
                                          # update the row in the distinct db table with OrgName/NetName or netname/irt
                                               
                                               # make sure the vars are not too large, lets trim them down to size
                                                   $who_OrgName = substr($who_OrgName, 0,28);
                                                   $who_NetName = substr($who_NetName, 0,28);
                                                   
                                         #print "Updating Database IP: $ip2check Reputation: $reputation\n";
                                      
                                          $dbh = DBI->connect( $dsn, $username, $password, \%attr );
                                          
                                          my $sql_update_statement = "UPDATE DistinctDests SET DstIpOrg = ?, NetName = ? WHERE DstIP = ?";
                                      
                                          $dbh->do($sql_update_statement,undef,$who_OrgName, $who_NetName, $ip2check, ) or die "Cannot Execute Update: $DBI::err , $DBI::errstr";
                                      
                                          $dbh->disconnect();
                                          
                                           std_log_evt("Updated Org [$who_OrgName] and NetName [$who_NetName] For Ip Address: $ip2check ");
                                           
                                                                                print "Updated Org [$who_OrgName] and NetName [$who_NetName] For Ip Address: $ip2check \n";
                                     
                                  } elsif (($who_netname) ||($who_irt)){
                                     
                                     print "FinalB: $who_irt, $who_netname \n ";
                                          # update the row in the distinct db table with OrgName/NetName or netname/irt
                                          
                                                                                    
                                               # make sure the vars are not too large, lets trim them down to size
                                                   $who_irt = substr($who_irt, 0,28);
                                                   $who_netname = substr($who_netname, 0,28);

                       
                                         print "Updating Database IP: $ip2check OrgName\n";
                                      
                                          $dbh = DBI->connect( $dsn, $username, $password, \%attr );
                                          
                                          my $sql_update_statement = "UPDATE DistinctDests SET DstIpOrg = ?, NetName =? WHERE DstIP = ?";
                                      
                                          $dbh->do($sql_update_statement,undef,$who_irt, $who_netname, $ip2check, ) or die "Cannot Execute Update: $DBI::err , $DBI::errstr";
                                      
                                          $dbh->disconnect();                                     
                                          
                                           std_log_evt("Updated Org [$who_irt] and NetName [$who_netname] For Ip Address: $ip2check ");
                                     print "Updated Org [$who_irt] and NetName [$who_netname] For Ip Address: $ip2check \n";
                                     
                                  } else {
                                     
                                     # Updating with Unk Data as org or netname was found
                                     
                                          $dbh = DBI->connect( $dsn, $username, $password, \%attr );
                                          
                                          my $sql_update_statement = "UPDATE DistinctDests SET DstIpOrg = ?, NetName =? WHERE DstIP = ?";
                                      
                                          $dbh->do($sql_update_statement,undef,"UnknownOrg", "UnknownNetName", $ip2check, ) or die "Cannot Execute Update: $DBI::err , $DBI::errstr";
                                      
                                          $dbh->disconnect();  
                                     
                                  }
                                  

                           
                           
                           # should be good to go.
                           
            } else {
             
             #okay there was no IP addresses left that need updating
                print "Currently, No Ip Address found needing the Orgname updated.... \n";
               std_log_evt("Currently, No Ip Address found needing the Orgname updated....");
             
             
            }
        
    
 
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

    my $logfile = "$log_dir" . "SocketSurveyer_Reputation_Worker_Std_Log";
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







sub update_distinct_dst_table {

    my ($in_str) = @_;
    
    std_log_evt("Updating Destination in the Distinct Db Table: $in_str");

    my ($DstIp, $DstIpHostname, $DstIpCity, $DstIpRegion, $DstIpCountry, $DstIpLoc, $DstIpOrg, $DstIpPostal) = split( /\|/, $in_str );
    
    
                    
                if ($DstIpPostal =~ /^\d+$/) {
                         # Okay, looks like a  number
                      } else {
                     # need to give it an integer value
                     $DstIpPostal = 0; 
                    }
   
     # Ensure we trim all variables to the proper database table field lengths or mysql will gripe
     $DstIpHostname = trim_input_43($DstIpHostname);
   

     $DstIpRegion = trim_input_43($DstIpRegion);   


     $DstIpCountry = trim_input_18($DstIpCountry);
     
     $DstIpOrg = trim_input_28($DstIpOrg);   


     $DstIpLoc = trim_input_28($DstIpLoc);
     

     $DstIpCity = trim_input_43($DstIpCity);
     
     eval { #### Start Eval - Trap Simultaneous inputs #####
     
    
    # MySQL database configurations
    my $dsn      = "DBI:mysql:socketdb";

    # connect to MySQL database
    my %attr = ( PrintError => 0, RaiseError => 1 );
    my $dbh = DBI->connect( $dsn, $username, $password, \%attr );

    $dbh->do('INSERT INTO DistinctDests (DstIp,DstIpHostname,DstIpCity,DstIpRegion,DstIpCountry,DstIpLoc,DstIpOrg,DstIpPostal,stamp_created,stamp_updated)
             VALUES (?,?,?,?,?,?,?,?,?,?)', undef, $DstIp, $DstIpHostname, $DstIpCity, $DstIpRegion, $DstIpCountry, $DstIpLoc, $DstIpOrg, $DstIpPostal, undef, undef);

    std_log_evt("Distinct Table Insert Complete : $in_str");
    
            };   ##### End Eval #####

}



sub trim_input_43 {

    my ($invar) = @_;
    
   my $ret_var = substr($invar, 0,43);
        return($ret_var);
    
}


sub trim_input_28 {

    my ($invar) = @_;
    my $ret_var = substr($invar, 0,28);
     return($ret_var);   
}

sub trim_input_18 {

    my ($invar) = @_;
    my $ret_var = substr($invar, 0,18);
    return($ret_var);
    
}

