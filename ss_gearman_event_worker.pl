#!/usr/bin/env perl
#
# SocketsSurveyor Event Worker Daemon V1
# Receives Rflow Events from the Rflow Receiver Daemon and Processes them - Runs as instances of Gearman Clients so you can run as many as needed to load balance a high number of events to process
# Performs basic Enrichment of Ip addresses by looking up basic information about them and adding it to the event row in the database
# Intended to try the Mojolicious Minion Worker but it did not support Mysql at the time of creation
#
#  Version 2 is underway as this version is becoming unwieldy as I continue to extend it, will break into more modular parts (modules)
#
# MIT License Copyright (c) [2018] [Mark Mollenkopf]
#


use strict;
use warnings;
use DBI;
use Gearman::Worker;
use WWW::ipinfo;
use GeoIP2::Database::Reader;
use Fcntl qw(:flock);
use Cwd qw(cwd);

my $ipinfo_ctr;
my $prosecute_internal_tfc; 
my $log_to_file ; 
my $print_to_stdout; 
my $path_to_geoip2_db;
my $perform_ipinfo_lookups; 
my $internal_iprange;
my $workdir = cwd;
my $log_dir;
my $unused;
my @fancy;

########## Configuration #######################################
$log_dir = $workdir . "/logs/"; #path to log dir default is .+log
$prosecute_internal_tfc = "OFF"; # OFF or ON
$log_to_file = "ON";            # OFF or ON
$print_to_stdout = "ON";        # OFF or ON
$path_to_geoip2_db =  $workdir . "/geolibs/current/GeoLite2-City.mmdb"; # This path should lead to your geolibs DB
$perform_ipinfo_lookups = "OFF";    # OFF or ON lookup from ipinfo.io
$internal_iprange = "192.168";   # this is your internal network range, the processor needs to know what is your internal network so it knows whats outbound or internal traffic to prosecute
my $username = "rick";  # database server username
my $password = '2!sTurKs';  # database server password

################################################################







sub process_event_fn {

    my $invar = $_[0]->arg;
    #my ($invar) = @_;
    std_log_evt("\n++BEGIN++\n Worker Received Rflow Event: $invar");  
    my $sanitized_input = sanitize_input($invar);
    $invar = $sanitized_input;
    std_log_evt("Sanitizing and Processing $invar");    

    my $src_hostname;
    my $dst_hostname;
    my $dst_str;
    my $src_str;
    my $final_str;

    my ( $epoc, $SrcIp, $SrcPort, $DstIp, $DstPort, $Packets, $Bytes, $Proto, $StartTime, $EndTime ) = split( /\|/, $invar );

    std_log_evt("Evaluating SRC: $SrcIp or DST: $DstIp Addresses");

    if ( ( $SrcIp =~ /$internal_iprange/i ) && ( $DstIp =~ /$internal_iprange/i ) ) {
        
            if ($prosecute_internal_tfc eq "OFF") {

                # Okay, Don't Even try to prosecute Internal Traffic
                
                std_log_evt("Both $SrcIp and $DstIp Matched Internal Range - Internal Only Traffic Prosecution Is OFF, Skipping Event...");

                # next;  

                
            } else {
                        
                # Okay, Prosecute Internal Traffic - WARNING!!! Not well supported today
                
                std_log_evt("Prosecuting Internal Traffic between $SrcIp and $DstIp In Specified Internal Address Range...");

                $src_hostname = search_for_intranet_host($SrcIp);
        
                $dst_hostname = search_for_intranet_host($DstIp);
        
                $final_str = "$SrcIp|$src_hostname|UNK|UNK|UNK|UNK|UNK|UNK|$DstIp|$dst_hostname|UNK|UNK|UNK|UNK|UNK|UNK|$SrcPort|$DstPort|$Packets|$Bytes|$Proto||";
        
                final_db_insert($final_str);
                
            }

    } elsif ( $SrcIp =~ /$internal_iprange/i ) {
        
        # Looks like Outbound Traffic, lets prosecute accordingly

        std_log_evt("$SrcIp Matched Internal Range...");

        $src_hostname = search_for_intranet_host($SrcIp);
        
        $dst_str      = search_ip_svc($DstIp);
        
        my ($y_hostname, $y_city,   $y_region, $y_country, $y_loc, $y_org, $y_netname,  $y_postal, $y_surv,   $y_remarks ) = split( /\|/, $dst_str );

        $final_str = "$SrcIp|$src_hostname|UNK|UNK|UNK|UNK|UNK|0|$DstIp|$y_hostname|$y_city|$y_region|$y_country|$y_loc|$y_org|$y_netname|$y_postal|$SrcPort|$DstPort|$Packets|$Bytes|$Proto|$y_surv|$y_remarks";

        ### Place Holder for 10 Factor Evaluation Processor sub Call (ML Lib Kit API Call 003)
        
        
        ### Return 10 Factor Eval Processor Sub Call
        
        
        final_db_insert($final_str);

    }  elsif ( $DstIp =~ /$internal_iprange/i ) {
        
        # Looks like Inbound Traffic, lets prosecute accordingly

        std_log_evt("$DstIp Matched Internal Range...");

        $dst_hostname = search_for_intranet_host($DstIp);
        $src_str      = search_ip_svc($SrcIp);
        my ( $x_hostname, $x_city,   $x_region, $x_country, $x_loc, $x_org, $x_netname, $x_postal, $x_surv,   $x_remarks ) = split( /\|/, $src_str );
     
        $final_str = "$SrcIp|$x_hostname|$x_city|$x_region|$x_country|$x_loc|$x_org|$x_postal|$DstIp|$dst_hostname|UNK|UNK|UNK|UNK|UNK|$x_netname|0|$SrcPort|$DstPort|$Packets|$Bytes|$Proto|$x_surv|$x_remarks";
 
         ### Place Holder for 10 Factor Evaluation Processor
         
         ### Return 10 Factor Eval Processor Sub Call
         
        final_db_insert($final_str);

    }
    else {

        err_log_evt( "ERROR-01 Neither Source($SrcIp) nor Dest($DstIp) IP was A Local Ip Address - Input: \"$invar\" ");

    }
}










sub final_db_insert {

    my ($in_str) = @_;
    
    std_log_evt("Final DB Insert of String: $in_str");

    my (
        $SrcIp,        $SrcIpHostname, $SrcIpCity, $SrcIpRegion,
        $SrcIpCountry, $SrcIpLoc,      $SrcIpOrg,  $SrcIpPostal,
        $DstIp,        $DstIpHostname, $DstIpCity, $DstIpRegion,
        $DstIpCountry, $DstIpLoc,      $DstIpOrg,  $NetName, $DstIpPostal,
        $SrcPort,      $DstPort,       $Packets,   $Bytes,
        $Proto,        $SurveyRslts,   $Remarks
    ) = split( /\|/, $in_str );

                
                if ($DstIpPostal =~ /^\d+$/) {
                         # Okay, looks like a  number
                      } else {
                     # need to give it an integer value
                     $DstIpPostal = 0; 
                    }
 
              if ($SrcIpPostal =~ /^\d+$/) {
                         # Okay, looks like a  number
                      } else {
                        # need to give it an integer value
                     $SrcIpPostal = 0; 
                    }
  
   
     $DstIpHostname = trim_input_43($DstIpHostname);
     $SrcIpHostname = trim_input_43($SrcIpHostname);
     
     $SrcIpRegion = trim_input_18($SrcIpRegion);   
     $DstIpRegion = trim_input_43($DstIpRegion);   

     $SrcIpCountry = trim_input_18($SrcIpCountry);   
     $DstIpCountry = trim_input_18($DstIpCountry);
     
     $DstIpOrg = trim_input_28($DstIpOrg);   
     $SrcIpOrg = trim_input_28($SrcIpOrg);
     
     $SrcIpLoc = trim_input_28($SrcIpLoc);   
     $DstIpLoc = trim_input_28($DstIpLoc);
     
     $SrcIpCity = trim_input_43($SrcIpCity);   
     $DstIpCity = trim_input_43($DstIpCity);
   
     $SurveyRslts = trim_input_43($SurveyRslts);   
     $Remarks = trim_input_43($Remarks);     
     
    # MySQL database configurations
    my $dsn      = "DBI:mysql:socketdb";
    
    # connect to MySQL database
    my %attr = ( PrintError => 0, RaiseError => 1 );
    my $dbh = DBI->connect( $dsn, $username, $password, \%attr );

    $dbh->do('INSERT INTO tabel1 (SrcIp,SrcIpHostname,SrcIpCity,SrcIpRegion,SrcIpCountry,SrcIpLoc,
             SrcIpOrg,SrcIpPostal,DstIp,DstIpHostname,DstIpCity,DstIpRegion,DstIpCountry,
             DstIpLoc,DstIpOrg,NetName,DstIpPostal,SrcPort,DstPort,Packets,Bytes,Proto,SurveyRslts,Remarks,
             stamp_created,stamp_updated)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        undef,          $SrcIp,    $SrcIpHostname, $SrcIpCity,   $SrcIpRegion,
        $SrcIpCountry,  $SrcIpLoc, $SrcIpOrg,      $SrcIpPostal, $DstIp,
        $DstIpHostname, $DstIpCity,
        $DstIpRegion, $DstIpCountry, $DstIpLoc, $DstIpOrg, $NetName, $DstIpPostal,
        $SrcPort,     $DstPort,
        $Packets, $Bytes, $Proto, $SurveyRslts, $Remarks, undef, undef
    );

    $dbh->disconnect();

}





sub search_ip_svc {

    my ($ip_addr) = @_;
    
    my $sanitized_ip = sanitize_input($ip_addr);

    $ip_addr = $sanitized_ip;

    std_log_evt("About to Check if $ip_addr already exists in sql db table");

    #first check if we've searched for this already in the main table
    my $pre_existing_ip_info = search_for_existing_entry($ip_addr);

    std_log_evt("Prexist Check Results: $pre_existing_ip_info");

    if ( $pre_existing_ip_info ne "FAILED" ) {

                # Okay it already exists - just return the existing host string
                
                std_log_evt("Prexisting Search +++ Success, Returning Result = $pre_existing_ip_info");
                return $pre_existing_ip_info;

        } else {
        
            # okay, prexist lookup failed, it didnt exist in distinct table, trying lookup using IP Info -provided its not throttled       
            if ($perform_ipinfo_lookups eq "ON") {
                
                std_log_evt("ipinfo.io Lookups are ON... Looking up $ip_addr");
                
                my $info_service_retval = ipinfo_lookup($ip_addr);
                
                std_log_evt("ipinfo.io Lookup Results = $info_service_retval");
                
                # Update the DistinctDest Table
                
                my $distinct_updatevar = "$ip_addr|$info_service_retval";
                
                update_distinct_dst_table($distinct_updatevar);
                    
                return $info_service_retval; #return the value to the original caller
            
        } else {
                
                # Okay, Gather Ip Address Info Manually   
                
                std_log_evt("Performing GeoIP Db Lookup for: $ip_addr");
                my $geo_retval = geoip2_lookup($ip_addr);
                
                my ($g_cityname, $g_countrycode) = split( /\|/, $geo_retval );

                std_log_evt("Performing Command Line Whois Lookup for: $ip_addr");                
                my ($whois_orgname_retval, $whois_netname_retval) = whois_lookup($ip_addr);

                std_log_evt("Performing Dig Command Line Lookup for: $ip_addr");                
                my $dig_hostname_retval = dig_lookup($ip_addr);

                my $manual_retval = "$dig_hostname_retval|$g_cityname||$g_countrycode||$whois_orgname_retval|$whois_netname_retval|";
                
                std_log_evt("Final Manual Lookup Return Value = $manual_retval");
                
                # Update the DistinctDest Table
                
                my $distinct_updatevar = "$ip_addr|$manual_retval";                
                
                update_distinct_dst_table($distinct_updatevar);
                
                return $manual_retval;
                
        }
    }
}





sub update_distinct_dst_table {

    my ($in_str) = @_;
    
    std_log_evt("Inserting New Destination Into Distinct Table: $in_str");

    my ($DstIp, $DstIpHostname, $DstIpCity, $DstIpRegion, $DstIpCountry, $DstIpLoc, $DstIpOrg, $NetName, $DstIpPostal) = split( /\|/, $in_str );
    
    
                    
                if ($DstIpPostal =~ /^\d+$/) {
                         # Okay, looks like a  number
                      } else {
                     # need to give it an integer value
                     $DstIpPostal = 0; 
                    }
   
     # Ensure we trim all variables to the proper database table lengths 
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

    $dbh->do('INSERT INTO DistinctDests (DstIp,DstIpHostname,DstIpCity,DstIpRegion,DstIpCountry,DstIpLoc,DstIpOrg,NetName,DstIpPostal,stamp_created,stamp_updated)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)', undef, $DstIp, $DstIpHostname, $DstIpCity, $DstIpRegion, $DstIpCountry, $DstIpLoc, $DstIpOrg, $NetName,$DstIpPostal, undef, undef);

    std_log_evt("Distinct Table Insert Complete : $in_str");
    
            };   ##### End Eval #####

}






sub ipinfo_lookup {  # Stopped using this for now because they want an account built and key to be issued YAT! (Yet Another Thing to mess with - perhaps later)
       
    my ($ip_addr) = @_;
    
    my $sanitized_ip = sanitize_input($ip_addr);

    $ip_addr = $sanitized_ip;

    std_log_evt("Performing IpInfo.io Ip Address Info Lookup for IP:$ip_addr ... \n Ipinfo CTR: $ipinfo_ctr");
    
    my $ipinf_retval;
    my $ipinfo;                
    
    $ipinfo_ctr++;
    
    eval { $ipinfo = get_ipinfo("$ip_addr"); };
    
    if ($@) {
        
        err_log_evt("ERROR Looking Up IP INFO.IO $@") if $@;
        
        std_log_evt("Turning OFF Ipinfo.io Lookups as err $@ was encountered!!");
        
        $perform_ipinfo_lookups = "OFF";
        
        print" ERROR Looking Up ipinfo $@ \n";
                
    }
        my $s_hostname = $ipinfo->{hostname};
        my $s_city     = $ipinfo->{city};
        my $s_region   = $ipinfo->{region};
        my $s_country  = $ipinfo->{country};
        my $s_loc      = $ipinfo->{loc};
        my $s_org      = $ipinfo->{org};
        my $s_postal   = $ipinfo->{postal};
        
        $ipinf_retval = "$s_hostname|$s_city|$s_region|$s_country|$s_loc|$s_org|$s_postal";

        std_log_evt("Completed ipinfo.io lookup heres the retval: $ipinf_retval");
    
    return $ipinf_retval;
  
}



sub dig_lookup {

    my ($ip_addr) = @_;
    
    my $sanitized_ip = sanitize_input($ip_addr);

    $ip_addr = $sanitized_ip;

    std_log_evt("Performing Cmd Line Dig Hostname Lookup for IP:$ip_addr ...");

    my $host;
    
    eval { $host = `dig +noall +answer -x $ip_addr`; };

    if ($@) {
        err_log_evt("ERROR During Commmand Line Hostname Dig Looking Up $ip_addr - $@") if $@;
        print" ERROR Looking Up Dig Hostname $@ \n";
    }
    
    my ($it0, $it1, $it2, $it3, $it4) = split(' ', $host);
    
    my $hostname = $it4;

        if ($hostname) {

          std_log_evt("Dig Command Successfully returned: $hostname");

        }else {

          $hostname = "UNK";

          std_log_evt("Dig Command Returned Zero Results, Returning UNK");
        }
        
    return $hostname;
}






sub whois_lookup {
    
    my ($ip_addr) = @_;
    
    my $sanitized_ip = sanitize_input($ip_addr);

    $ip_addr = $sanitized_ip;

    std_log_evt("Performing Cmd Line Whois Lookup for IP:$ip_addr ...");
    

                                 my $who_OrgName;
                                 my $who_NetName;
                                 my $who_irt;
                                 my $who_netname;
                                 
                                 my @retval;
                                 
                                eval {  @retval = `/usr/bin/whois $ip_addr`; }; # this requires whois binary installed on linux host 
                                 
                                 if ($@) {
                                     err_log_evt("ERROR During Commmand Line Whois Looking Up for $ip_addr - $@") if $@;
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
                                  
                                  
                                std_log_evt("Manual Whois Net and Org Lookup Retrieved: Org: $who_OrgName, NetName: $who_NetName, netname: $who_netname, irt: $who_irt");
                                      
                                  if (($who_OrgName) || ($who_NetName)) {
                                            
                                            # return these two
                                                    # but first make sure the vars are not too large, lets trim them down to size
                                                   $who_OrgName = substr($who_OrgName, 0,28);
                                                   $who_NetName = substr($who_NetName, 0,28);
                                                   
                                                return ("$who_OrgName", "$who_NetName");
                                            
                                  }  elsif (($who_netname) ||($who_irt)){
                                    
                                            # return these two then
                                                    # but first make sure the vars are not too large, lets trim them down to size
                                                   $who_irt = substr($who_OrgName, 0,28);
                                                   $who_netname = substr($who_NetName, 0,28);
                                                   
                                                return ("$who_netname", "$who_irt");
                                            
                                  }  else {
                                     
                                     # Updating with Unk Data as org or netname was found
                                         return ("UnknownOrg", "UnknownNetName");
                                     
                                  }

    
}




sub geoip2_lookup {
    
    my ($ip_addr) = @_;
    
    my $sanitized_ip = sanitize_input($ip_addr);

    $ip_addr = $sanitized_ip;

    std_log_evt("Looking Up IP:$ip_addr in GeoIP2 Database...");
    
        my $reader = GeoIP2::Database::Reader->new(
        file    => "$path_to_geoip2_db",
        locales => [ 'en', 'de', ]
    );
     
        my $ip_localchk = $ip_addr;
        my $where_is;
        my $lat;
        my $long;
        my $location;
        my $nearest_city;
        my $city_name;
        my $country;
        my $country_code;
        
    
    eval {
        
        $where_is = $reader->city( ip => $ip_localchk );
        $location = $where_is->location;
        ($lat, $long) = ($location->latitude, $location->longitude);
        $nearest_city = $where_is->city;
        $city_name = $nearest_city->name;
        $country = $where_is->country();
        $country_code = $country->iso_code();                  
          
          };
    
        if ($@) {
                    err_log_evt("ERROR Looking Up IP INFO.IO $@") if $@;
                    print" ERROR Looking Up ipinfo $@ \n";
                    
        }


    my $ipinf_retval = "$city_name|$country_code";
    std_log_evt("Returning GeoIP2 Results(City,Country):$ipinf_retval ...");
    return $ipinf_retval;
    
    
    
}






sub search_for_existing_entry {

    my ($ip_to_check) = @_;
    
    my $sanitized_ip = sanitize_input($ip_to_check);

    $ip_to_check = $sanitized_ip;

    std_log_evt("Entered Search for Existing entry Sub: $ip_to_check");

    # Database vars
    my $dsn      = "DBI:mysql:socketdb";
    my %attr     = ( PrintError => 0, RaiseError => 1 );

    # connect to MySQL database
    my $dbh = DBI->connect( $dsn, $username, $password, \%attr );
    std_log_evt("About to Perform Prexist check on: $ip_to_check");

    my $sth = $dbh->prepare("SELECT * FROM socketdb.DistinctDests where DstIp = \"$ip_to_check\" ORDER BY stamp_updated DESC LIMIT 1;");
    $sth->execute();

    my $row;
    my $ctr;
    my $DstIp;
    my $DstIpHostname;
    my $DstIpCity;
    my $DstIpRegion;
    my $DstIpCountry;
    my $DstIpLoc;
    my $DstIpOrg;
    my $NetName;
    my $DstIpPostal;
    my $SurveyRslts;
    my $Remarks;
    my $ret_val;

    while ( my $row = $sth->fetchrow_hashref() ) {
        
        $ctr++;
        $DstIp         = $row->{DstIp};
        $DstIpHostname = $row->{DstIpHostname};
        $DstIpCity     = $row->{DstIpCity};
        $DstIpRegion   = $row->{DstIpRegion};
        $DstIpCountry  = $row->{DstIpCountry};
        $DstIpLoc      = $row->{DstIpLoc};
        $DstIpOrg      = $row->{DstIpOrg};
        $NetName       = $row->{NetName};
        $DstIpPostal   = $row->{DstIpPostal};
        $SurveyRslts   = $row->{SurveyRslts};
        $Remarks       = $row->{Remarks};
        
        $ret_val = "$DstIpHostname|$DstIpCity|$DstIpRegion|$DstIpCountry|$DstIpLoc|$DstIpOrg|$NetName|$DstIpPostal|$SurveyRslts|$Remarks";
       
        std_log_evt("Existing Entry Query result = $ret_val -- Counter= $ctr");

    }
    if (! defined $ctr) {
        
        std_log_evt("Existing DB Entry Lookup Failed, Returning FAILED [ReturnedVal: $ret_val]");

        $sth->finish();
        
        return "FAILED";
 
    }  else {
        
       std_log_evt("Exsisting DB Entry Lookup Succeeded, Returning Var: $ret_val");

        $sth->finish();

        return "$ret_val";

    }
}




sub search_for_intranet_host {

    my ($ip_to_check) = @_;
    
    my $sanitized_ip = sanitize_input($ip_to_check);

    $ip_to_check = $sanitized_ip;

    std_log_evt("Search Lookup List for Internal Ip Range Hostname: $ip_to_check");

    my $dsn      = "DBI:mysql:socketdb";
    my %attr     = ( PrintError => 0, RaiseError => 1 );

    my $returned_hostname;

    my $dbh = DBI->connect( $dsn, $username, $password, \%attr );

    my $sth = $dbh->prepare("SELECT hostname FROM socketdb.int_hosts where ip = \"$ip_to_check\"; ");

    $sth->execute();

    my ($var) = $dbh->selectrow_array($sth);
    
    $sth->finish();

    $dbh->disconnect();
    
    if ($var) {
        std_log_evt("Sucessful Internal look up, Returning $var");
        return "$var";
    }
    else {
        std_log_evt("Failed Internal look up, Returning Unk-Internal");
        return "Unk-Internal";
    }



}


sub sanitize_input {
    
    my ($dirty_invar) = @_;
    $dirty_invar =~ s/([;<>\*`&\$!#\(\)\[\]\{\}:'"])//g; # Allow | and . 
    $dirty_invar =~ s/[a-z]//gi; # Allow Integers
    my $sanitized_output = $dirty_invar;
    return $sanitized_output;
  
  }



sub err_log_evt {

    my ($invar) = @_;
    chomp($invar);
    my ( $DAY, $MONTH, $YEAR ) = (localtime)[ 3, 4, 5 ];
    $YEAR  = $YEAR + 1900;
    $MONTH = $MONTH + 1;

    if ( $MONTH < 10 ) { $MONTH = "0" . "$MONTH"; }
    if ( $DAY < 10 )   { $DAY   = "0" . "$DAY"; }
    my $FQDTG = "$YEAR$MONTH$DAY";

    # my $logfile = "$mypath/"; # Later
    my $logfile = "$log_dir" . "SocketSurveyer_Gearman_Worker_Err_Log";
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

sub std_log_evt {

    my ($invar) = @_;
    chomp($invar);
    my ( $DAY, $MONTH, $YEAR ) = (localtime)[ 3, 4, 5 ];
    $YEAR  = $YEAR + 1900;
    $MONTH = $MONTH + 1;

    if ( $MONTH < 10 ) { $MONTH = "0" . "$MONTH"; }
    if ( $DAY < 10 )   { $DAY   = "0" . "$DAY"; }
    my $FQDTG = "$YEAR$MONTH$DAY";

    my $logfile = "$log_dir" . "SocketSurveyer_Gearman_Worker_Std_Log";
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





my $worker = Gearman::Worker->new();
$worker->job_servers('127.0.0.1:4730');
$worker->register_function('process_event', \&process_event_fn);
$worker->work() while (1);



