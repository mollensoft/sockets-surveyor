#!/usr/bin/perl --
#
# SocketsSurveyor Web Server Daemon - Uses the Mojoliious framework to act as HTTP Server - in production, recommend using self-signed SSL/TLS certs for security,
#
#  _ Do Not Expose directly to the Internet! _  
#
#  Future Internet Employment will recommend the use of apache or nginx as reverse proxy back to this server daemon as its not designed for this type of exposure 
#
# This script serves as the Analyst Portal Interface where users log in and perform analysis of Netflow events capture and enriched by the SocketsSurveyor System
#
# This Server includes properly implemented Auth mechanisms but is NOT/NOT TLS enabled out of the box unless you enable it by generating Certs EXPECTATION IS THAT Apache or another server will sit in front of this with TLS
#
# Tried to implement with as little unnecessary javascript, CSS as possible focusing on utility and minimalism (will make it prettier and more intuitive later)
#
# 13 Nov 18, Okay Version 2 will definitely refactor this monster into properly organized Full App, Mojolicious server - Evolving this single script over time has made it a bit unwieldy 
#
# MIT License Copyright (c) [2019] [Mark Mollenkopf]
#


use Mojolicious::Lite;
use DBI;
use Mojo::Log;
use Crypt::PBKDF2;
use Net::Telnet::Gearman;
use Data::Dumper;
use Data::Validate::IP;
use Cwd qw(cwd);
use DateTime::Format::MySQL;
use Mojolicious::Plugin::Status; 

plugin 'Status'; # use Mojolicious Cool New HTTP Connection Status Feature

########## Configuration #######################################
my $workdir = cwd;
my $pub_dir = $workdir . "/public/reports/";
my $user = 'rick';        # MySQL Database Username for dbase and tables
my $password = '2!sTurKs'; # MySQL Database Password
my $password_file = $workdir . "/sockssurv_auth";

app->secrets(['9cLdkP69dkgRsdbaQZ27']);

########## EndConfiguration #######################################

### Run Me This Way On the Command Line for Dev server using Morbo or Production using preforking Daemon ###################################################################
##                                                                                                                                                                        ##
##     morbo -l http://[::]:80 ss_httpd.pl  ## Non-SSL/TLS Encrypted Development Server                                                                                   ##
##                                                                                                                                                                        ##
##     morbo -l 'https://*:443?cert=certs/mollensoft.crt&key=certs/mollensoft.key' ss_httpd.pl  ## SSL/TLS Encrypted Dev Server                                           ##
##                                                                                                                                                                        ##
##   or, for 'production' type use recommend starting  this script this way                                                                                               ##
##                                                                                                                                                                        ##
##      ./ss_httpd.pl prefork -m production -w 10 -c 1 -H 900 -G 900 -i 900 -l http://[::]:80 &     #production non-TLS Server                                            ##
##                                                                                                                                                                        ##
##      ./ss_httpd.pl prefork -m production -w 10 -c 1 -H 900 -G 900 -i 900 -l 'https://*:443?cert=certs/mollensoft.crt&key=certs/mollensoft.key' &  # Prod with TLS      ##
##                                                                                                                                                                        ##
############################################################################################################################################################################

########  Make Web Page Components Into Reusable Variables ######

my $navigation_page_footer = << 'END_OF_FOOTER';
	<nav>
			<h2>Navigation</h2>
			<ul>
				<li><a href="/login">Login</a></li>
				<li><a href="/adminpage">Control Panel</a></li>
        <br>
				<li><a href="/graphviewall">Summary Graphs All Devices</a></li>
				<li><a href="/graphviewdevice">Summary Graphs By Device</a></li>
        <br>        
				<li><a href="/summaryview">Summary-All Hosts (Slow!)</a></li>
        <br>
				<li><a href="/detailedhost">Detailed Events Report</a></li>
				<li><a href="/reputationrpt">Detailed Reputation Report</a></li>
        <br> 
        <li><a href="/dstportsrpt">Destination Ports Report</a></li>
        <li><a href="/destdetail">Destination Details</a></li>
        <li><a href="/zerodays">Zero Days Report</a></li>        
		<li><a href="/custom">Custom Date Time Queries</a></li>
		<li><a href="/stdev">Detect Outliers by Std Dev</a></li>
        
        <br>         
        <li><a href="/reports">Alert Email Reports Archive</a></li>
        <li><a href="/modhosts">Add/Remove Int Hosts</a></li>
        <li><a href="/status">Server Status</a></li>
        <li><a href="/changepassword">Change Account Password</a></li>
        <li><a href="/helpdocs">About, Help &amp; Documentation</a></li>
        <br>   
				<li><a href="/logout">Logout</a></li>
			</ul>
		</nav>
</body>
</html>
END_OF_FOOTER



my $web_page_header = << 'END_OF_HEADER';
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.7.2/Chart.bundle.min.js"></script>
    <meta charset="utf-8">
    <meta name="Analytic Interface" content="SocketsSurvyeor"><link href="/favicon-16x16.png" rel="icon" type="image/x-icon" />
	<title>Sockets Surveyor</title>
	<style type="text/css" media="screen">
		html, body, div, header, footer, aside, nav, article, section	{ margin: 0; padding: 0; }
		header, footer, aside, nav, article, section	{ display: block; }
		body 			{ color: #333; font: 12px Helvetica, Arial, sans-serif; line-height: 18px; }
		h2				{ color: #333; }
		a				{ color: #337810; }
		p				{ margin: 0 0 18px; }
		#wrapper		{ float: left; width: 100%; }
		
		/* Header */
		header			{ background: #333; border-bottom: 2px solid #aaa; }
		header h1  	{ color: #fff; margin: 0 0 3px; padding: 6px 10px 0; }
		header p		{ color: #ccc; font-size: 11px; font-weight: bold; padding: 0 18px; }
		
		/* Content Style */
		nav		{ border-bottom: 1px solid #ccc; padding-left: 18px; }
		nav ul	{ padding: 0 18px 9px; }
		#content		{ padding-left: 18px; }
		#extra			{ border-bottom: 1px solid #ccc; }
		#extra small	{ font-size: 11px; line-height: 18px; }
		#content p, #extra p { padding-right: 18px; }
		
		/* Content Positioning and Size */
		nav		{ float: left; width: 200px; margin-left: -100%; }
		#content		{ margin: 0 5% 36px 225px; }
		#extra			{ float: left; width: 31%; margin-left: -31%; }		/* Footer */
		footer			{ background: #666; border-bottom: 2px solid #aaa; clear: left; width: 100%; }
		footer a		{ color: #fff; }
		footer	p		{ color: #ccc; margin: 0; padding: 0 18px 10px; }
		footer ul		{ border-bottom: 1px solid #999; list-style: none; margin: 0 18px 6px; padding: 10px 0 6px; }
		footer li		{ display: inline; font-size: 11px; font-weight: bold; padding-right: 3px; }
                                table {
                                            font-family: arial, sans-serif;
                                            border-collapse: collapse;
                                            width:100%;
                                        }
                                        
                                        td, th {
                                            border: 1px solid #dddddd;
                                            text-align: left;
                                            padding: 1px;
                                        }
                                        
                                        tr:nth-child(even) {
                                            background-color: #dddddd;
                                        }
                                        </style>
	</style>
</head><body>
	<div id="container">
		<header>
			<h1><IMG src="/SocketsSurveyor.jpg" style="width:45px;height:45px;"> <B> Sockets Surveyor - </B> Enhancing Visibility of Your Internal Cyberspace!</h1><P>
		</header>
END_OF_HEADER



##### Set up/verify Passwords File ###
# Check for Auth/Password File Existence

if (-e $password_file) {
    
    # Okay it exists... do nothing (we'll log it in later revs)
    
} else {
    
    # File Does No Exist, Probably First Run So Create it
    open(my $outfile, '>', $password_file) or die "Could not open file '$password_file' $!";
    
    my $hashed_pass = hash_password("pass1");
    
    print $outfile "analyst|$hashed_pass";
    
    close $outfile;

}




sub hash_password {
  
      # accept input and return a SHA2 Salted HMAC
     my ($invar) = @_;
     
      my $pbkdf2 = Crypt::PBKDF2->new(
    	hash_class => 'HMACSHA2',
    	hash_args => {
    		sha_size => 512,
    	},
        iterations => 10000,
        salt_len => 10,
    );

    my $hashed_password = $pbkdf2->generate($invar);
    
    return $hashed_password;
}







sub check_password {
  
     my ($invar) = @_;
     
     my $password_hash;
     my $username;
     
        open(my $handl, '<:encoding(UTF-8)', $password_file) or die "Sockets Surveyor Auth File: $password_file Cannot be Opened, does it exist? Err( $! )";

                while (my $row = <$handl>) {
                  chomp $row;
                   ($username, $password_hash) = split(/\|/, $row);
          
                }

                  close $handl;
            
        my $pbkdf2 = Crypt::PBKDF2->new;
        
       if ($pbkdf2->validate($password_hash, $invar)) {
        
           return 1 ; # Okay Return 1 Which means its a password hash matches User Inputted Password
           
       } else {
  
           return 0; # Okay Return 0 Which means the user inputted password and the hash stored in the file was not.not a match indicating invalid Password entered (perhaps we throttle this in the future to limit attempts)

           
       }

}




app->attr(dbh => sub {
    
    my $self = shift;
    
    my $data_source = "dbi:mysql:socketdb:127.0.0.1";
    
    my $dbh = DBI->connect($data_source, $user, $password, , {RaiseError => 1, AutoCommit =>1, mysql_auto_reconnect=>1});
    
    return $dbh;
    
});



helper auth => sub {
  
  my $c = shift;
    
  my $uname =  $c->param('username') ; #
  
  if ($uname ne 'analyst') {
    
    # Okay the username is not correct so do not go any further, could be a bot
    
    return 0;
    
    }
    
  my $pwd   =  $c->param('password') ;
  
        if ((defined $uname && length $uname > 0) && (defined $pwd && length $pwd > 0)) {
          
                        # Opening Passwd File
                        
                        if (open(my $handl, '<:encoding(UTF-8)', $password_file)) {
                      
                        while (my $row = <$handl>) {
                      
                        chomp $row;
                      
                        my ($username, $password) = split(/\|/, $row);

                        # Checking Password....
                        
                        my $ret_val = check_password($pwd);
                        
                        if ($ret_val == 1) {
                          
                        # Password Hashes Do Match
                          
                          return 1;
                          
                        } else {
                        
                        # Password Hashes Do NOT.NOT Match
                          
                          return 0;
                          
                        }
                    
                      }
                      
                    } else {
                      
                        warn "Could not open file '$password_file' $! - \n Creating it now \n";
                        
                        # Okay, its not there, let's create the auth-passwd file
                        
                        open(my $outfile, '>', $password_file) or die "Could not open file '$password_file' $!";
                        
                        my $hashed_pass = hash_password("pass1");
                        
                        # Print to the Outfile: $outfile "analyst|$hashed_pass" Keep it simple
                        
                        close $outfile;
                        
                        # Okay, We Are Done Creating default Password File - Hope this was the first Run or someone Recovering their system  
                          
                    } 

        } else {
          
          # Okay, not authenticated, responding with 0
          
           return 0;

        }
    # return 0; #default false response - probably not needed if we did our job
};



get '/index' => sub { shift->render } => 'index';


get '/' => sub {
   
  my $c = shift;
  
   my $isauthd = $c->auth;
   
   if ($isauthd == 1) {
    
    $c->redirect_to('adminpage'); # Every Authenticated user should be directed here
  
  } else {
    
     $c->redirect_to('index');  # Okay, cannot authenticate, lets send the client back to root
    
  }

};



any '/login' => sub {

  my $c = shift;

  if ($c->auth) {

    $c->session(auth => 1);
    $c->session(expiration => 9600);

    return $c->redirect_to('adminpage');

  }

  $c->flash('error' => 'Wrong login/password');

  $c->redirect_to('index');

} => 'login';




get '/logout' => sub {
  
  my $c = shift;
  
  delete $c->session->{auth};
  
  $c->redirect_to('index');
  
} => 'logout';







under sub {
  
  my $c = shift;
  
  return 1 if ($c->session('auth') // '') eq '1';
  
  $c->flash('error' => 'Incorrect login/password or Session Expired');
  
  $c->redirect_to('index');
  
  return undef;
  
};



## Very Cool Server Status - Quite Useful In having visibility of activity
plugin Status => {route => app->routes->any('/status'), return_to => 'adminpage' };



#############################################################
######### All Subs below Here Require Authentication ########
#############################################################





get '/modhosts' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
    
  # Fetch Available Parameters and sanitize 
  my $action = $self->param("action") ;
  my $newip = $self->param("newipaddress") ;
  my $remove_ip = $self->param("ip") ;
  my $newhostname = $self->param("newhostname"); 
  
  $action =~ s/[^a-zA-Z0-9]//g; #Actions Should Only be number, letter
  
  my $sanitized_ip = sanitize_input($remove_ip);
     $remove_ip = $sanitized_ip; # sanitize the ip to remove
  
  my $santized_host = sanitize_hostnames($newhostname);  # sanitize the new hostname
  $newhostname = $santized_host;
  $newhostname = substr($newhostname, 0,43); # Trim The user Input to meet the SQL servers table, Field Length
  
  my $sanitized_input = sanitize_input($newip); # sanitize the new ip
  $newip = $sanitized_input;

  # Add Items to Stash For future Use
  $self->stash( newhostname => $newhostname );
  $self->stash( newip => $newip );
  

  
  if ($action == 1) {
       
        if ((defined $remove_ip && length $remove_ip > 0)) {
        
                  ## Validate the IP Address is an IP
                  
                     if (is_ipv4($remove_ip)) {
                                          
                  ## okay lets delete the record from the Internal Hosts Table
                  
                                     my $dbh = $self->app->dbh;
          
                                     my $sth = $dbh->prepare('delete from socketdb.int_hosts where ip = ?');
                                        
                                     $sth->execute($remove_ip);                  
                  
                                 ## Send a Message of our action     
 
                                 $self->stash( responsemsg => "<P> <H2 style=\"color:Red;\">Removed IP Address: $remove_ip </H2>" ); # set response message
                        
                     } else {
                        
                        
                          $self->stash( responsemsg => "<P> <H2 style=\"color:Red;\">IP Address is Malformed </H2>" ); # set response message
                        
                     }
        
        }  else {
            
               ## Send a Error Message Indicating The IP Address was missing     
                      $self->stash( responsemsg => "<P> <H2 style=\"color:Red;\">Error: No IP Address was Submitted for Removal  </H2>" ); # set response message
        }
        

    
  } elsif ($action == 2) {
    
    
                if ((defined $newip && length $newip > 0) && (defined $newhostname && length $newhostname > 0)) {
                
                  
                           ## Validate the IP Address is in fact an IP Address                       
                            if (is_ipv4($newip)) {
                              
                              # Check to see if an Entry Already Exists with that Address
                               
                               my $dbh = $self->app->dbh;
                                                                   
                               my $sth = $dbh->prepare('SELECT ip FROM socketdb.int_hosts where ip = ?;');
    
                                $sth->execute($newip);
                                
                                my $rowctr;
                                 while ( my $row = $sth->fetchrow_hashref() ) {
        
                                        $rowctr++;                                    
                                 }
                                
                                
                                
                                if (defined $rowctr) {
                                    
                                    # Oops, there's already an entry
                                    
                                     $self->stash( responsemsg => "<P>  <H2 style=\"color:Red;\">Error: IP Address Already Exists in Database</H2>" ); # set response message                                         
                                     
                                } else {
                              
                                    # Input the new IP Address and Hostname into the database server
                                    
                                     my $dbh = $self->app->dbh;
          
                                     my $sth = $dbh->prepare('insert into socketdb.int_hosts values(?,?)');
                                        
                                     $sth->execute($newip,$newhostname);
                                  
                                     $self->stash( responsemsg => "<P>  <H2 style=\"color:Green;\">Added IP Address: $newip  and Host: $newhostname</H2>" ); # set response message                                   
                                    
                                    
                                    
                                }
                              
                              

                            
                            } else {
                                
                                # The User Submitted IP Address Is MalFormed
                                
                                     $self->stash( responsemsg => "<P>  <H2 style=\"color:Red;\">IP Address Was Malformed, please Retry</H2>" ); # set response message
                               
                            }

                
                } else {
                    
                    # Okay something was missing return an error
                     $self->stash( responsemsg => "<P>  <H2 style=\"color:Red;\">Error: IP Address $newip Was Malformed or Missing or Host Was Missing</H2>" ); # set response message
                    
                }
 
     

  } else {
    
    # Okay, nothing to add or remove, just print the default page with a helper sentence amplifying what the user can do on this page
    
    $self->stash( responsemsg => "<P> <B>Click \"[Remove Host]\" to Permanently remove the IP Address from Tracking or Type In A New Hostname and Ip Address to Begin Tracking </B>" ); # set response message
             
  }
  
  
    ### On All Paths - Show the updated list
    my $dbh = $self->app->dbh;
    
    my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
      
    $sth->execute;
      
    my $rows3 = $sth->fetchall_arrayref;
         
    $self->stash( rows3 => $rows3 );
    
    $self->stash( resptype => 0 );
      
 $self->render('modhosts');
  
};






get '/stdev' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $qip = $self->param("ip") ;
  
  my $sanitized_input = sanitize_input($qip);
  
  $qip = $sanitized_input;
 
  my $qtime = $self->param("time");  ### Validate & SANITIZE 
  $qtime = sanitize_numbers_only($qtime);
  
  my $qhost = $self->param("host"); ### Validate & SANITIZE
   $qhost =~ s/[^a-zA-Z0-9]//g; # Lets Only allow numbers and letters for hostnames
  
  $self->stash( internalhost => $qhost ); 

  $self->stash( querytime => $qtime );
  
  $self->stash( bytesX5 => 0 );
 
  my $dbh = $self->app->dbh;

  my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
    
  $sth->execute;
    
  my $rows3 = $sth->fetchall_arrayref;
  
      my $rows4; my $rows5; my $rows6;
      
     $self->stash( rows4 => $rows4, rows5 => $rows5 ,rows6 => $rows6  );
     
         $self->stash( resptype => 0 ); # set response type as no query data as a default
       
  $self->stash( rows3 => $rows3 );
  
          if ((defined $qhost && length $qhost > 0) && (defined $qtime && length $qtime > 0)) {


                    # first fetch Upper byte limit, 5 Standard Deviations from the Average Byte Count for this host to DEST Web Servers
                  $sth = $dbh->prepare('SELECT truncate(avg(bytes), 0)  + truncate(stddev(bytes),0) + truncate(stddev(bytes),0) + truncate(stddev(bytes),0) + truncate(stddev(bytes),0) +
                                       truncate(stddev(bytes),0) as  upperlimit5 FROM socketdb.tabel1 where proto = 6 and ((DstPort = 443) or (DstPort = 80))
                                       and SrcIpHostname = ? and stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR)');
                    
                  $sth->execute($qhost,$qtime);
                    
                  my $std_dev_bytes = $sth->fetchrow_array();
                  $std_dev_bytes = sanitize_numbers_only($std_dev_bytes);
                    $self->stash( bytesX5 => $std_dev_bytes );

                    
                  $sth = $dbh->prepare('SELECT tabel1.Bytes, tabel1.stamp_created, tabel1.SrcIpHostname, DistinctDests.Reputation, tabel1.DstIp, tabel1.DstIpHostname, tabel1.DstIpOrg,
                                       tabel1.NetName, tabel1.SurveyRslts FROM socketdb.tabel1 INNER JOIN DistinctDests On tabel1.DstIp = DistinctDests.DstIp  where tabel1.Bytes
                                       > ? and tabel1.proto = 6  and ((tabel1.DstPort = 443) or (tabel1.DstPort = 80)) and tabel1.SrcIpHostname = ?
                                       AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR)  order by tabel1.stamp_created asc');

                 $sth->execute($std_dev_bytes, $qhost, $qtime);
                   
                  $rows4 = $sth->fetchall_arrayref;
               
                 $self->stash( rows4 => $rows4 );
               
              $self->stash( resptype => 1 ); # set query response type as returning query data 
         
          }
 
  $self->render('stdev');
                
};





get '/detailedhost' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $qip = $self->param("ip") ;
  
  my $sanitized_input = sanitize_input($qip);
  
  $qip = $sanitized_input;
 
  my $qtime = $self->param("time");
  $qtime =~ s/[^0-9]//g; # Lets ensure this is only Integer Hours
  
  my $qhost = $self->param("host"); 
  
  $self->stash( internalhost => $qhost ); 

  $self->stash( querytime => $qtime );
 
  my $dbh = $self->app->dbh;

  my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
    
  $sth->execute;
    
  my $rows3 = $sth->fetchall_arrayref;
  
      my $rows4; my $rows5; my $rows6;
      
     $self->stash( rows4 => $rows4, rows5 => $rows5 ,rows6 => $rows6  );
     
         $self->stash( resptype => 0 ); # set response type as no query data as a default
       
  $self->stash( rows3 => $rows3 );
  
          if ((defined $qhost && length $qhost > 0) && (defined $qtime && length $qtime > 0)) {
                    
                  $sth = $dbh->prepare('SELECT tabel1.SrcIpHostname, DistinctDests.Reputation, tabel1.DstIp, count(*) as Counter, tabel1.DstIpHostname, tabel1.DstIpOrg, tabel1.NetName, tabel1.SurveyRslts FROM socketdb.tabel1
                  INNER JOIN DistinctDests On tabel1.DstIp = DistinctDests.DstIp where SrcIpHostname = ? AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR) group
                  by tabel1.DstIp order by Counter desc limit 100');
                  
                 $sth->execute($qhost, $qtime);
                   
                  $rows4 = $sth->fetchall_arrayref;
               
                 $self->stash( rows4 => $rows4 );
               
             
               
          $self->stash( rows4 => $rows4 );
        
        
                  $sth = $dbh->prepare('SELECT tabel1.SrcIpHostname, DistinctDests.Reputation, tabel1.DstIp, count(*) as Counter, tabel1.DstIpHostname, tabel1.DstIpOrg, tabel1.NetName, tabel1.SurveyRslts FROM socketdb.tabel1
                  INNER JOIN DistinctDests On tabel1.DstIp = DistinctDests.DstIp where SrcIpHostname = ? AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR) group
                  by tabel1.DstIp order by Counter asc limit 100');
                  
                 $sth->execute($qhost, $qtime);
                   
                  $rows5 = $sth->fetchall_arrayref;
               
                 $self->stash( rows5 => $rows5 );
               
        
                  $sth = $dbh->prepare('SELECT sum(tabel1.Bytes), DistinctDests.Reputation, tabel1.DstIp, tabel1.DstIpHostname, tabel1.DstIpOrg, tabel1.NetName FROM socketdb.tabel1
                  INNER JOIN DistinctDests On tabel1.DstIp = DistinctDests.DstIp where SrcIpHostname = ? AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR) group
                  by tabel1.DstIp order by sum(tabel1.Bytes) desc ;');
                  
          $sth->execute($qhost, $qtime);
              
           $rows6 = $sth->fetchall_arrayref;
         
          $self->stash( rows6 => $rows6 );
          
          $self->stash( resptype => 1 ); # set query response type as returning query data 
         
          }
 
  $self->render('detailedhost');

};









any '/exechistory' => sub {

  my $self = shift;
  
  #
  # This subroutine is called via XmlHttpRequest (XHR) by the destdetail subroutine
  # It populates the page with event data from all hosts that have outbound connections to the specified destination IP address
  #
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $qip = $self->param("ip") ;
   $qip = sanitize_input($qip);
  my $inline_dat; 
  $self->stash( respmesg2 => '' );
  $self->stash( resptype2 => '' ); 
    
    if (defined $qip && length $qip > 0) {
      
      # Okay there is user input in the address field lets validate its an IPV4 address
      
      
           if (is_ipv4("$qip")) {
            
            # Okay its a valid IPV4 Address - lets Exec the Sql Query
               
               
                  $self->stash( resptype2 => 2 ); # User Input is Valid
                  $self->stash( respmesg2 => "Processing IP Address $qip" ); 
           
                  my $dbh = $self->app->dbh;
                
                  my $sth = $dbh->prepare('SELECT stamp_created, SrcIp, SrcIpHostname, SrcPort, DstIp, DstIpHostname, DstIpCity, DstIpCountry,
                                          DstIpOrg , NetName, DstPort, Packets, Bytes, Proto  FROM socketdb.tabel1 where DstIp = ?
                                          order by stamp_created >= DATE_SUB(NOW(), INTERVAL 30 DAY) limit 10000;');
                 
                  $sth->execute($qip);
                    
                  my $rows1 = $sth->fetchall_arrayref;
                  
                  # For this subroutine, lets try generating output in server side rather than the template 

                  $inline_dat = '<table border="1">';
                  $inline_dat .= '   <tr>';
                  $inline_dat .= '     <th>DTG</th>';
                  $inline_dat .= '     <th>Src IP</th>';
                  $inline_dat .= '     <th>Src Name</th> ';                                 
                  $inline_dat .= '     <th>Src Port</th>';
                  $inline_dat .= '     <th>Dest IP</th>';
                  $inline_dat .= '     <th>Dest Name</th>';
                  $inline_dat .= '     <th>Dest City</th>  ';                                
                  $inline_dat .= '     <th>Dest Country</th>';
                  $inline_dat .= '     <th>Dest Org</th>  ';
                  $inline_dat .= '     <th>Net Name</th>';
                  $inline_dat .= '     <th>Dest Port</th>';
                  $inline_dat .= '     <th>Packets</th>  ';
                  $inline_dat .= '     <th>bytes</th>';                                
                  $inline_dat .= '     <th>Proto</th>';
                  $inline_dat .= '     </tr>';
                  
                   $inline_dat .= "<b>Outbound Connections last 30 Days to Dest Ip Address:$qip (limit 10,000 items) </b> ";
                  
                      foreach my $item (@$rows1) {
                        $inline_dat .= "<tr> <td> $item->[0] </td><td>$item->[1] </td> <td>$item->[2]";
                        $inline_dat .= "</td> <td>$item->[3] </td><td>$item->[4]</td> <td>$item->[5] </td> <td>$item->[6] </td>
                        <td>$item->[7] </td><td>$item->[8] </td><td>$item->[9] </td><td>$item->[10] </td><td>$item->[11] </td><td>$item->[12] </td><td>$item->[13] </td></tr>";
                      }
                $inline_dat .= '</table> ';            

                       
           }  else {
            
            # Nope, the user input is not a valid IPV4 Address, Don't Query for it
            $self->stash( resptype2 => 3 ); # User Input Is not a valid IP Address
            $self->stash( respmesg2 => "Input was Not a Valid IPV4 Address" );
            
           }

      
    } else {
      
      # Okay, there is no user input, do nothing
        $self->stash( resptype2 => 0 ); # set resp type to zero indicating no user input

    }
    
  $self->render(inline => $inline_dat);  # trying a different method of catching input and generating output in server rather than the template

};



get '/fetchsummaryview' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
    
  my $dbh = $self->app->dbh;
  
  my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
    
  $sth->execute;
    
  my $rows3 = $sth->fetchall_arrayref;
  
  my @summary_dat;

  foreach my $item (@$rows3) {
    
       next if ($item->[1] eq '');

      $sth = $dbh->prepare('SELECT  SrcIpHostname, count(*), count(distinct DstIp), count(distinct DstIpOrg), count(distinct DstPort),
                           sum(Bytes) FROM socketdb.tabel1 where SrcIpHostname = ? AND stamp_created >=
                           DATE_SUB(NOW(), INTERVAL 24 HOUR) ;');
        
      $sth->execute($item->[1]);
        
      my $temp_dat = $sth->fetchall_arrayref;
      push @summary_dat, $temp_dat;
  }
#######################################

			     my $render_str = "<p><P> Summary of All Internal Hosts Activity Last 24 Hours</p>";

                              $render_str .= "<table border=\"1\">";
                              $render_str .=  "<tr>";
                              $render_str .=  "<th>Hostname</th>";
                              $render_str .=  "<th>Total Outbound Flows</th>";
                              $render_str .=  "<th>Distinct Destinations</th>";
                              $render_str .=  "<th>Distinct Dest Orgs </th>";
                              $render_str .=  "<th>Distinct Dest Ports </th>";
                              $render_str .=  " <th>Total Outbound Flows In MB </th></tr> ";
                                  
                              foreach my $item (@summary_dat) {
                                 next if ($item->[0][0] eq '');
                                 my $qval = sprintf("%.3f", $item->[0][5] / (1024 * 1024));
                                 $render_str .=  " <tr><td>$item->[0][0]</td><td>$item->[0][1]</td><td>$item->[0][2]</td><td>$item->[0][3]</td><td>$item->[0][4]</td><td>$qval</td></tr>";
                                 
                                 }
                              $render_str .=  "</table>";


  ##### Second Table Per host Query #####

  my @summary_dat2;

  foreach my $item (@$rows3) {
    
      $sth = $dbh->prepare('SELECT  SrcIpHostname, count(*), count(distinct DstIp), count(distinct DstIpOrg), count(distinct DstPort),
                           sum(Bytes) FROM socketdb.tabel1 where SrcIpHostname = ? AND stamp_created >=
                           DATE_SUB(NOW(), INTERVAL 168 HOUR) ;');
        
      $sth->execute($item->[1]);
        
      my $temp_dat2 = $sth->fetchall_arrayref;
      push @summary_dat2, $temp_dat2;
      
    
  }
  my $sumdat2 = \@summary_dat2;

			    $render_str .= "<p><P> Summary of All Internal Hosts Activity Last 7 Days</p>";

                              $render_str .= "<table border=\"1\">";
                              $render_str .=  "<tr>";
                              $render_str .=  "<th>Hostname</th>";
                              $render_str .=  "<th>Total Outbound Flows</th>";
                              $render_str .=  "<th>Distinct Destinations</th>";
                              $render_str .=  "<th>Distinct Dest Orgs </th>";
                              $render_str .=  "<th>Distinct Dest Ports </th>";
                              $render_str .=  " <th>Total Outbound Flows In MB </th></tr> ";
                                  
                              foreach my $item (@summary_dat2) {
                                 next if ($item->[0][0] eq '');
                                 my $qval = sprintf("%.3f", $item->[0][5] / (1024 * 1024));
                                 $render_str .=  " <tr><td>$item->[0][0]</td><td>$item->[0][1]</td><td>$item->[0][2]</td><td>$item->[0][3]</td><td>$item->[0][4]</td><td>$qval</td></tr>";
                                 
                                 }
                              $render_str .=  "</table>";

  ##### Third Table Per host Query #####

  my @summary_dat3;

  foreach my $item (@$rows3) {

      $sth = $dbh->prepare('SELECT  SrcIpHostname, count(*), count(distinct DstIp), count(distinct DstIpOrg), count(distinct DstPort),
                           sum(Bytes) FROM socketdb.tabel1 where SrcIpHostname = ? AND stamp_created >=
                           DATE_SUB(NOW(), INTERVAL 720 HOUR) ;');
        
      $sth->execute($item->[1]);
        
      my $temp_dat3 = $sth->fetchall_arrayref;
      push @summary_dat3, $temp_dat3;
  }
  
  
  my $sumdat3 = \@summary_dat3;

			    $render_str .= "<p><P> Summary of All Internal Hosts Activity Last 30 Days</p>";

                              $render_str .= "<table border=\"1\">";
                              $render_str .=  "<tr>";
                              $render_str .=  "<th>Hostname</th>";
                              $render_str .=  "<th>Total Outbound Flows</th>";
                              $render_str .=  "<th>Distinct Destinations</th>";
                              $render_str .=  "<th>Distinct Dest Orgs </th>";
                              $render_str .=  "<th>Distinct Dest Ports </th>";
                              $render_str .=  " <th>Total Outbound Flows In MB </th></tr> ";
                                  
                              foreach my $item (@summary_dat3) {
                                 next if ($item->[0][0] eq '');
                                 my $qval = sprintf("%.3f", $item->[0][5] / (1024 * 1024));
                                 $render_str .=  " <tr><td>$item->[0][0]</td><td>$item->[0][1]</td><td>$item->[0][2]</td><td>$item->[0][3]</td><td>$item->[0][4]</td><td>$qval</td></tr>";
                                 
                                 }
                              $render_str .=  "</table>";

    $self->render(inline => $render_str); # Lets try using inline rendering to see how it works

};







any '/summaryview' => sub {
  
  my $self = shift;
  
  # This subroutine /summaryview will call subroutine fetchsummaryview via XHR to generate inline content (see fetchsummaryview above for more details)
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  $self->render('summaryview');
    
};








get '/helpdocs' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
 
  $self->render('helpdocs');
                
};









any '/destdetail' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $dbh = $self->app->dbh;
  my $qip;
  
  my $qip_input = $self->param("ipaddress") ;
     $qip_input = sanitize_input($qip_input);
 
  $self->stash( respmesg => '' ); 
  
  $self->stash( respmesg2 => '' ); # needed for XHR in /exechistory sub to work
  $self->stash( resptype2 => 0 ); # needed for XHR in /exechistory sub to work
  
  $self->stash( qip => $qip_input );
  
  my $rows1;
  $self->stash( rows1 => $rows1 );
  
  my $rows2;
  $self->stash( rows2 => $rows2 );
  
  my $lastseen;
  $self->stash( lastseen => $lastseen );
   
  my $firstseen;
  $self->stash( firstseen => $firstseen );
  
  
      if (defined $qip_input && length $qip_input > 0) {
        
                $self->stash( resptype => 1 ); # set resp type 1, there is user input
        
                $self->stash( respmesg => "Processing $qip_input" ); 
        
                my $sanitized_input = sanitize_input($qip_input);
                $qip_input = $sanitized_input;
                 
                    
         # There is input in ipaddress param now lets check it for validity
                 
        
            if (is_ipv4("$qip_input")) {
                       
                $self->stash( resptype => 2 ); # User Input is Valid
                 $qip = $qip_input;      
                 $self->stash( qip => $qip );
                  $self->stash( respmesg => "Processing IP Address $qip" ); 
                
                  my $sth = $dbh->prepare('SELECT DstIp, DstIpHostname, DstIpRegion, DstIpCountry, DstIPOrg, NetName, Reputation FROM socketdb.DistinctDests where DstIp = ? order by uid desc limit 1;');
                    
                  $sth->execute($qip);
                    
                 $rows1 = $sth->fetchall_arrayref;
                       
                  $self->stash( rows1 => $rows1 );           
  
                  $sth = $dbh->prepare('SELECT stamp_created FROM socketdb.tabel1 where DstIp = ? order by uid desc limit 1;');
                    
                  $sth->execute($qip);
                    
                   $lastseen = $sth->fetchrow_array(); 
                       
                  $self->stash( lastseen => $lastseen );
                  
                 
                  
                   $sth = $dbh->prepare('SELECT stamp_created FROM socketdb.tabel1 where DstIp = ? order by uid asc limit 1');
                    
                  $sth->execute($qip);
                    
                  $firstseen = $sth->fetchrow_array(); 
                       
                  $self->stash( firstseen => $firstseen );
                  
                 
                   $sth = $dbh->prepare('SELECT  distinct SrcIpHostname, SrcIp FROM socketdb.tabel1 where DstIp = ?');
                    
                  $sth->execute($qip);
                    
                  $rows2 = $sth->fetchall_arrayref;
                       
                  $self->stash( rows2 => $rows2 );
                  

            } else {
              # Okay its not a IPV4 Ip Address
       
               $self->stash( respmesg => "Input was Not a Valid IPV4 Address" );
               $self->stash( resptype => 3 ); # User Input Is not a valid IP Address 
              
            }
                
        
      }  else {
        
        # Okay, there is No ip address param - just render plain
        
          $self->stash( resptype => 0 ); # set resp type to zero indicating no user input

      }

  $self->render('destdetail');
    
};











any '/graphviewall' => sub {
  
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $dbh = $self->app->dbh;
  
  my $sth = $dbh->prepare('SELECT stamp_created, count(*) as counter FROM socketdb.tabel1  where tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 168 HOUR) GROUP BY hour( stamp_created ) , day( stamp_created )  order by stamp_created asc;');
    
  $sth->execute();
  
    my $dtg;
    my $count;
    my $ctr;
    my $chart_colors_str = " backgroundColor: [";
    my $chart_labels_str = "labels: [";
    my $chart_values_str = "data: [";
  
  while ( my $row = $sth->fetchrow_hashref() ) {
    
        $ctr++;
        $dtg = $row->{stamp_created};
        $count = $row->{counter};
       
       $dtg =~ s/://g;
        
      chop($dtg);
      chop($dtg);
      $chart_values_str .=  "$count,";
      $chart_labels_str .=  "\"$dtg\",";
      $chart_colors_str .= "\"#3e95cd\",";
    
  }
  
  chop($chart_values_str);
  chop($chart_labels_str);
  chop($chart_colors_str);
      $chart_values_str .=  "]";
      $chart_labels_str .=  "],";
      $chart_colors_str .=  "],";
 
  $self->stash( chart_values_str => $chart_values_str );
  $self->stash( chart_labels_str => $chart_labels_str );
  $self->stash( chart_colors_str => $chart_colors_str );
  
  #######################################  
  
  
   $sth = $dbh->prepare('SELECT stamp_created, count(*) as counter FROM socketdb.tabel1  where tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 720 HOUR) GROUP BY hour( stamp_created ) , day( stamp_created ) order by stamp_created asc ;');
  
    
  $sth->execute();
  
  
    my $dtg2;
    my $count2;
    my $chart_colors_str2 = " backgroundColor: [";
    my $chart_labels_str2 = "labels: [";
    my $chart_values_str2 = "data: [";
  
  while ( my $row2 = $sth->fetchrow_hashref() ) {
    
        $dtg2 = $row2->{stamp_created};
        $count2 = $row2->{counter};
       
       $dtg2 =~ s/://g;
        
      chop($dtg2);
      chop($dtg2);
      $chart_values_str2 .=  "$count2,";
      $chart_labels_str2 .=  "\"$dtg2\",";
      $chart_colors_str2 .= "\"#3e92cd\",";
    
  }
  
  chop($chart_values_str2);
  chop($chart_labels_str2);
  chop($chart_colors_str2);
      $chart_values_str2 .=  "]";
      $chart_labels_str2 .=  "],";
      $chart_colors_str2 .=  "],";
 
  $self->stash( chart_values_str2 => $chart_values_str2 );
  $self->stash( chart_labels_str2 => $chart_labels_str2 );
  $self->stash( chart_colors_str2 => $chart_colors_str2 );
  
 
    $self->render('graphviewall');
    
};



any '/graphviewdevice' => sub {
  
  # Render Graph of Device activity By Device using Chart.js
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );

  my @records;
  
  my $dbh = $self->app->dbh;

  my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
    
  $sth->execute;
    
  my $rows3 = $sth->fetchall_arrayref;
  
  my @summary_dat;

  foreach my $item (@$rows3) {
    
       next if ($item->[1] eq '');
       
        my $sth = $dbh->prepare('SELECT stamp_created, count(*) as counter FROM socketdb.tabel1  where   tabel1.SrcIpHostname = ? AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 168 HOUR) GROUP BY hour( stamp_created ) , day( stamp_created )  order by stamp_created asc;');
    
        $sth->execute($item->[1]);
        
          my $dtg;
          my $count;
          my $ctr;
          my $chart_colors_str = " backgroundColor: [";
          my $chart_labels_str = "labels: [";
          my $chart_values_str = "data: [";
        
        while ( my $row = $sth->fetchrow_hashref() ) {
          
              $ctr++;
              $dtg = $row->{stamp_created};
              $count = $row->{counter};

             $dtg =~ s/://g;
              
            chop($dtg);
            chop($dtg);
            $chart_values_str .=  "$count,";
            $chart_labels_str .=  "\"$dtg\",";
            $chart_colors_str .= "\"#3e95cd\",";
          
        }
        
        chop($chart_values_str);
        chop($chart_labels_str);
        chop($chart_colors_str);
            $chart_values_str .=  "]";
            $chart_labels_str .=  "],";
            $chart_colors_str .=  "],";
            
       my $devrecord = { "name" => $item->[1],  "labels" => $chart_labels_str,  "values" => $chart_values_str, "colors" => $chart_colors_str   };
      
     push @records, $devrecord;
 
  
  } # end of rpt by device loop 7 Day
  
  
  ##### Now Get 30 day Stats Per each Device ##########
  
  my @records2;
  
  foreach my $item (@$rows3) {
    
       next if ($item->[1] eq '');
       
        my $sth = $dbh->prepare('SELECT stamp_created, count(*) as counter FROM socketdb.tabel1  where   tabel1.SrcIpHostname = ? AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL 720 HOUR) GROUP BY hour( stamp_created ) , day( stamp_created )  order by stamp_created asc;');
    
        $sth->execute($item->[1]);
        
          my $dtg;
          my $count;
          my $ctr;
          my $chart_colors_str2 = " backgroundColor: [";
          my $chart_labels_str2 = "labels: [";
          my $chart_values_str2 = "data: [";
        
        while ( my $row = $sth->fetchrow_hashref() ) {
          
              $ctr++;
              $dtg = $row->{stamp_created};
              $count = $row->{counter};

             $dtg =~ s/://g;
               
            chop($dtg);
            chop($dtg);
            $chart_values_str2 .=  "$count,";
            $chart_labels_str2 .=  "\"$dtg\",";
            $chart_colors_str2 .= "\"#3e95cd\",";
          
        }
        
        chop($chart_values_str2);
        chop($chart_labels_str2);
        chop($chart_colors_str2);
            $chart_values_str2 .=  "]";
            $chart_labels_str2 .=  "],";
            $chart_colors_str2 .=  "],";
            
       my $devrecord = { "name" => $item->[1],  "labels" => $chart_labels_str2,  "values" => $chart_values_str2, "colors" => $chart_colors_str2   };
      
     push @records2, $devrecord;
 
  
  } # end of rpt by device 30 day query loop
  
    
      $self->stash( records => \@records );
      
      $self->stash( records2 => \@records2 );
            
      $self->render('graphviewdevice');
    
};



get '/reputationrpt' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $qip = $self->param("ip") ;

  my $sanitized_input = sanitize_input($qip);

  $qip = $sanitized_input;
  
  my $qtime = $self->param("time"); ### SANITIZE 
  $qtime = sanitize_numbers_only($qtime);
  
  my $qhost = $self->param("host"); ### SANITIZE
  $qhost=sanitize_hostnames($qhost);
  
  $self->stash( internalhost => $qhost );

  $self->stash( querytime => $qtime );
 
  my $dbh = $self->app->dbh;

  my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
    
  $sth->execute;
    
  my $rows3 = $sth->fetchall_arrayref;
       
  $self->stash( rows3 => $rows3 );
  
    $self->stash( resptype => 0 );
    
    my $rows4 ;
    
    $self->stash( rows4 => $rows4  );
  
if ((defined $qhost && length $qhost > 0) && (defined $qtime && length $qtime > 0)) {
  
          $sth = $dbh->prepare('SELECT tabel1.SrcIpHostname, DistinctDests.Reputation, tabel1.DstIp, count(*) as Counter, tabel1.DstIpHostname, tabel1.DstIpOrg, tabel1.NetName, tabel1.SurveyRslts FROM socketdb.tabel1
          INNER JOIN DistinctDests On tabel1.DstIp = DistinctDests.DstIp where SrcIpHostname = ? AND DistinctDests.Reputation = 3 AND tabel1.stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR) group
          by tabel1.DstIp order by Counter desc limit 100');
             
         $sth->execute($qhost, $qtime);
           
         $rows4 = $sth->fetchall_arrayref;
       
         $self->stash( rows4 => $rows4 );
         $self->stash( resptype => 1 );
    } 
  $self->render('reputationrpt');
};




###############
###############





get '/zerodays' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  $self->stash( rowcount => 0 );
  
  my $qip = $self->param("ip") ;
  my $sanitized_input = sanitize_input($qip);
  $qip = $sanitized_input;
  
  my $qtime = $self->param("time"); ###  SANITIZE
  
  $qtime= sanitize_numbers_only($qtime);
  
  my $qhost = $self->param("host"); ###  SANITIZE
  
  $qhost=sanitize_hostnames($qhost); 
  
  $self->stash( internalhost => $qhost );

  $self->stash( querytime => $qtime );
 
  my $dbh = $self->app->dbh;

  my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
    
  $sth->execute;
    
  my $rows3 = $sth->fetchall_arrayref;
       
  $self->stash( rows3 => $rows3 );
  
    $self->stash( resptype => 0 );
    
    my $rows4 ;
    
    $self->stash( rows4 => $rows4  );
  
      if ((defined $qhost && length $qhost > 0) && (defined $qtime && length $qtime > 0)) {
        
     
                $sth = $dbh->prepare('SELECT tabel1.SrcIpHostname, DistinctDests.Reputation, DistinctDests.stamp_created,  tabel1.DstIp, count(*) as Counter, sum(tabel1.Bytes) as bytecount,
                                     tabel1.DstIpHostname, tabel1.DstIpOrg, tabel1.NetName, tabel1.SurveyRslts FROM socketdb.tabel1 INNER JOIN DistinctDests On
                                     tabel1.DstIp = DistinctDests.DstIp where SrcIpHostname = ? AND DistinctDests.stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                                     group by tabel1.DstIp order by Counter desc limit 1000;');
                   
               $sth->execute($qhost, $qtime);
               my $rowcount = $sth->rows;
                 
               $rows4 = $sth->fetchall_arrayref;
             
               $self->stash( rows4 => $rows4 );
               $self->stash( rowcount => $rowcount );
               $self->stash( resptype => 1 );

      } 

  $self->render('zerodaysrpt');
  
};






get '/dstportsrpt' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $qip = $self->param("ip") ;
  my $sanitized_input = sanitize_input($qip);
  $qip = $sanitized_input;
  
  my $qtime = $self->param("time"); ### SANITIZE
    $qtime= sanitize_numbers_only($qtime);
  
  my $qhost = $self->param("host"); ### SANITIZE
  $qhost=sanitize_hostnames($qhost);
  
  $self->stash( internalhost => $qhost );

  $self->stash( querytime => $qtime );
 
  my $dbh = $self->app->dbh;

  my $sth = $dbh->prepare('SELECT ip, hostname FROM socketdb.int_hosts order by hostname desc ;');
    
  $sth->execute;
    
  my $rows3 = $sth->fetchall_arrayref;
       
  $self->stash( rows3 => $rows3 );
  
    $self->stash( resptype => 0 );
    
    my $rows4 ;
    
    $self->stash( rows4 => $rows4  );
  
      if ((defined $qhost && length $qhost > 0) && (defined $qtime && length $qtime > 0)) {
        
      
                $sth = $dbh->prepare('SELECT  count(DstPort), DstPort, Proto, DstIpHostname, DstIpOrg, NetName, DstIp FROM socketdb.tabel1 where SrcIpHostname = ? AND stamp_created >= DATE_SUB(NOW(), INTERVAL ? HOUR)
                                     group by DstIp order by count(DstPort) desc');
                   
               $sth->execute($qhost, $qtime);
                 
               $rows4 = $sth->fetchall_arrayref;
             
               $self->stash( rows4 => $rows4 );
               $self->stash( resptype => 1 );

      } 

  $self->render('dstportsrpt');
  
};


get '/custom' => sub {
  
  # a short subroutine to query the dbase for all events between a start date time and end date time
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $table_str; 
  
  my $dbh = $self->app->dbh;
  
  my $start_input = $self->param("startdatetime") ;

  my $end_input = $self->param("enddatetime") ;
  
  $self->stash( resptype => 0 ); # set response type to user input error = false

  $self->stash( respmesg => '' ); # set response type to user input error = true

  if  ((defined $start_input && length $start_input > 0) && (defined $end_input && length $end_input > 0) ) {
    
      # okay, we've got form input start and stop date time lets validate its format
      eval { my $dt = DateTime::Format::MySQL->parse_datetime($start_input);  };
      
      my $dtgerr =0;
 
      if( $@ ) { $dtgerr++; }
      
      eval { my $dt = DateTime::Format::MySQL->parse_datetime($end_input);  };
 
     if( $@ ) { $dtgerr++; }

        if ($dtgerr > 0) {
          
            $self->stash( resptype => 1 ); # set response type to user input error = true
            $self->stash( respmesg => 'Start or End Date Incorrectly Formatted' ); # set response type to user input error = true

         } else {

                  $self->stash( resptype => 0 ); # set response type to user input error = false
            
                  $self->stash( startdtg => $start_input );
          
                  $self->stash( enddtg => $end_input );       
                  
           
            my $sth = $dbh->prepare('SELECT stamp_created, SrcIp, SrcIpHostname, SrcPort, DstIp, DstIpHostname, DstIpCity, DstIpCountry,
                                    DstIpOrg , NetName, DstPort, Packets, Bytes, Proto  FROM socketdb.tabel1 where stamp_created between ? and ? limit 10000;');
              
            $sth->execute($start_input,$end_input);
            my $rowcount = $sth->rows;
              
            my $rows1 = $sth->fetchall_arrayref;
           
                                        $table_str = '<table border="1">';
                                        $table_str .= '   <tr>';
                                        $table_str .= '     <th>DTG</th>';
                                        $table_str .= '     <th>Src IP</th>';
                                        $table_str .= '     <th>Src Name</th> ';                                 
                                        $table_str .= '     <th>Src Port</th>';
                                        $table_str .= '     <th>Dest IP</th>';
                                        $table_str .= '     <th>Dest Name</th>';
                                        $table_str .= '     <th>Dest City</th>  ';                                
                                        $table_str .= '     <th>Dest Country</th>';
                                        $table_str .= '     <th>Dest Org</th>  ';
                                        $table_str .= '     <th>Net Name</th>';
                                        $table_str .= '     <th>Dest Port</th>';
                                        $table_str .= '     <th>Packets</th>  ';
                                        $table_str .= '     <th>bytes</th>';                                
                                        $table_str .= '     <th>proto</th>';
                                        $table_str .= '     </tr>';
                                       
                                         $table_str .= "<b> $rowcount Outbound Connection Events From: [$start_input]  To: [$end_input]  </b> ";
                                       
                                           foreach my $item (@$rows1) {
                                              $table_str .= "<tr> <td> $item->[0] </td><td>$item->[1] </td> <td>$item->[2]";
                                              $table_str .= "</td> <td>$item->[3] </td><td>$item->[4]</td> <td>$item->[5] </td> <td>$item->[6] </td>
                                             <td>$item->[7] </td><td>$item->[8] </td><td>$item->[9] </td><td>$item->[10] </td><td>$item->[11] </td><td>$item->[12] </td><td>$item->[13] </td></tr>";
                                           }
                                      $table_str .= '</table> ';  
             $self->stash( table_str =>  $table_str );
        }
  } else {
    #okay, no form data 
 }
 $self->render('custom');
};


get '/reports' => sub {
  
  # Simply get a list of historical text reports and list them for the client
 
   my $self = shift;
   
   ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
   
   my $report_str;
    
   my @dir_list = glob("$pub_dir*.txt");
   
   foreach my $item (@dir_list) {
    
    $item =~ s/$pub_dir//ig;
    
    $report_str .=  "<a href=\"/reports/$item\">$item</a><br>";
    
   }

   $self->stash( report_str =>  $report_str );
   
   $self->render('reportview');
    
};


############# CHANGE PASSWORD!#############

any '/changepassword' => sub {
  
  my $self = shift;
  
  ## Add header and footer to every request
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
  
  my $dbh = $self->app->dbh;

  my $password1 = $self->param("password1") ;
  my $password2 = $self->param("password2") ;
  
    $self->stash( responsemsg => "Attempting to Change existing Analyst Password" );
             
   if ( $password1 ne '' &&  $password2 ne '' ) {
    
              # Okay, Passwords Are Not empty       
         
         if ($password1 eq $password2) {
           
              # Okay Passwords Matched!     
           
             my $password_final = $password2;
             
             # Okay user is authenticated lets change the password now
            
              open(my $outfile, '>', $password_file) or die "Could not open file '$password_file' $!";
              
              my $hashed_pass = hash_password($password_final);
              
              print $outfile "analyst|$hashed_pass";
              
              close $outfile;
              
              # Done Creating default Password File 
              
              $self->stash( responsemsg => "Password Successfully Changed!" );
      
         } else {
                   
             # Passwords Did NOT.NOT Match 

               $self->stash( responsemsg => "The Passwords you Entered Did Not Match, Please try again" );
         }
   } else {
    # Okay, The Password form fields are empty
      $self->stash( responsemsg => "Username and Password Fields Currently Empty" );
   }
  $self->render('changepassword');
};





get '/:cp/:target/:command' => sub {
  
  my $self = shift;


  ## Add header and footer to every request 
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
 ##############################
 
  $self->stash( cmd_warning  => '' );
   
   my $cp = $self->param('cp');
   my $target = $self->param('target');
   my $command = $self->param('command');
   
   if (($cp eq 'cp') && ($target =~ /reputation|flow|daily|dbytes|watcher|event/) && ($command =~ /start|stop/)) {
    
    # okay the target is a valid control panel command
     print "debug: cp == cp \n";
     
        if (($target eq 'reputation') && ($command eq 'stop')) { kill_ReputationWorker(); }
        if (($target eq 'reputation') && ($command eq 'start')) { init_ReputationWorker(); }    
        
        if (($target eq 'flow') && ($command eq 'stop')) { kill_FlowWorker(); }
        if (($target eq 'flow') && ($command eq 'start')) { init_FlowWorker(); }       
 
        if (($target eq 'daily') && ($command eq 'stop')) { kill_DailyWorker(); } 
        if (($target eq 'daily') && ($command eq 'start')) { init_DailyWorker(); }
        
        if (($target eq 'watcher') && ($command eq 'stop')) { kill_WatcherWorker(); } 
        if (($target eq 'watcher') && ($command eq 'start')) { init_WatcherWorker(); }      
        
        if (($target eq 'event') && ($command eq 'stop')) { kill_EventWorker(); } 
        if (($target eq 'event') && ($command eq 'start')) { init_EventWorker(); }         

        if (($target eq 'dbytes') && ($command eq 'stop')) { kill_deltabytesalerter(); } 
        if (($target eq 'dbytes') && ($command eq 'start')) { init_deltabytesalerter(); }   

   } else {
    
    # Bad Request, send them a warning and continue rendering the admin page

         $self->stash( cmd_warning  => 'Command Not Understood!' );
    
   }

        ## Now update the adminpage with fresh stats


        # Verify Reputation Worker Status        
        my $ret_val = checkstat_ReputationWorker();
        my $rep_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $rep_startstopper = "Running <a href=\"/cp/reputation/stop\">[Stop]</a>";
         
        } else {
         
              $rep_startstopper = "Stopped <a href=\"/cp/reputation/start\">[Start]</a>";
         
        }
        
        # Verify Flow Receiver Worker Status        
        my $ret_val = checkstat_rflowRcvr();
        my $flow_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $flow_startstopper = "Running <a href=\"/cp/flow/stop\">[Stop]</a>";
         
        } else {
         
              $flow_startstopper = "Stopped <a href=\"/cp/flow/start\">[Start]</a>";
         
        }

       # Verify Daily Reporter Worker Status        
        my $ret_val = checkstat_dailyreporter();
        my $dailyrptr_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $dailyrptr_startstopper = "Running <a href=\"/cp/daily/stop\">[Stop]</a>";
         
        } else {
         
              $dailyrptr_startstopper = "Stopped <a href=\"/cp/daily/start\">[Start]</a>";
         
        }        



       
       # Verify dbytes Alerter Status        
        my $ret_val = checkstat_deltabytesalerter();
        my $dbytes_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $dbytes_startstopper = "Running <a href=\"/cp/dbytes/stop\">[Stop]</a>";
         
        } else {
         
              $dbytes_startstopper = "Stopped <a href=\"/cp/dbytes/start\">[Start]</a>";
         
        }        
               

        
        
       # Verify Watcher Worker Status        
        my $ret_val = checkstat_watcherreporter();
        my $watcher_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $watcher_startstopper = "Running <a href=\"/cp/watcher/stop\">[Stop]</a>";
         
        } else {
         
              $watcher_startstopper = "Stopped <a href=\"/cp/watcher/start\">[Start]</a>";
         
        }        
               
        
       # Verify Event Worker Status        
        my $ret_val = checkstat_EventWorker();
        my $eventwkr_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $eventwkr_startstopper = "Running <a href=\"/cp/event/stop\">[Stop]</a>";
         
        } else {
         
              $eventwkr_startstopper = "Stopped <a href=\"/cp/event/start\">[Start]</a>";
        }        
      
         $self->render('adminpage', local_ip => fetch_ip(), local_hostname => fetch_hostname(), EventWorker_status => $eventwkr_startstopper, RflowListner_status => $flow_startstopper, checkstat_watcherreporter => $watcher_startstopper,
                       checkstat_dailyreporter => $dailyrptr_startstopper, checkstat_deltabytesalerter => $dbytes_startstopper, gearmand_status => checkstat_gearmand(), gman_workstat => fetch_workerstats(),
                       reputation_workstat => $rep_startstopper);

};






get '/adminpage' => sub { 
  
  my $self = shift;
  $self->stash( cmd_warning  => '' );

  ## Add header and footer to every request 
  $self->stash( web_page_header  => $web_page_header  );
  $self->stash( navigation_page_footer  => $navigation_page_footer  );
 ##############################

        ## Now update the adminpage with fresh stats

        # Verify Reputation Worker Status        
        my $ret_val = checkstat_ReputationWorker();
        my $rep_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $rep_startstopper = "Running <a href=\"/cp/reputation/stop\">[Stop]</a>";
         
        } else {
         
              $rep_startstopper = "Stopped <a href=\"/cp/reputation/start\">[Start]</a>";
         
        }
        
        # Verify Flow Receiver Worker Status        
        my $ret_val = checkstat_rflowRcvr();
        my $flow_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $flow_startstopper = "Running <a href=\"/cp/flow/stop\">[Stop]</a>";
         
        } else {
         
              $flow_startstopper = "Stopped <a href=\"/cp/flow/start\">[Start]</a>";
         
        }

       # Verify Daily Reporter Worker Status        
        my $ret_val = checkstat_dailyreporter();
        my $dailyrptr_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $dailyrptr_startstopper = "Running <a href=\"/cp/daily/stop\">[Stop]</a>";
         
        } else {
         
              $dailyrptr_startstopper = "Stopped <a href=\"/cp/daily/start\">[Start]</a>";
         
        }        



        
       # Verify DeltaBytes Alerter Status        
        my $ret_val = checkstat_deltabytesalerter();
        my $dbytes_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $dbytes_startstopper = "Running <a href=\"/cp/dbytes/stop\">[Stop]</a>";
         
        } else {
         
              $dbytes_startstopper = "Stopped <a href=\"/cp/dbytes/start\">[Start]</a>";
         
        }        
               


        
        
       # Verify Watcher Worker Status        
        my $ret_val = checkstat_watcherreporter();
        my $watcher_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $watcher_startstopper = "Running <a href=\"/cp/watcher/stop\">[Stop]</a>";
         
        } else {
         
              $watcher_startstopper = "Stopped <a href=\"/cp/watcher/start\">[Start]</a>";
         
        }        
               
    
       # Verify Event Worker Status        
        my $ret_val = checkstat_EventWorker();
        my $eventwkr_startstopper;
        
        if ($ret_val eq 'Running') {
         
              $eventwkr_startstopper = "Running <a href=\"/cp/event/stop\">[Stop]</a>";
         
        } else {
         
              $eventwkr_startstopper = "Stopped <a href=\"/cp/event/start\">[Start]</a>";
         
        }        
                           
        
         $self->render('adminpage', local_ip => fetch_ip(), local_hostname => fetch_hostname(), EventWorker_status => $eventwkr_startstopper, RflowListner_status => $flow_startstopper,
                       checkstat_watcherreporter => $watcher_startstopper, checkstat_deltabytesalerter => $dbytes_startstopper, checkstat_dailyreporter => $dailyrptr_startstopper, gearmand_status => checkstat_gearmand(),
                       gman_workstat => fetch_workerstats(), reputation_workstat => $rep_startstopper);

};





### Fetch System Info ###

sub fetch_ip {
  my $n = shift;
  my $getval = `hostname -I`;
  return $getval 
}


sub fetch_hostname {
  my $n = shift;
  my $getval = `hostname`;
  return $getval 
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



 ###########################
sub checkstat_EventWorker {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_gearman_event_worker.pl" | grep -v grep | wc -l`;
  if ($shellval >= 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}


sub kill_EventWorker {
  my $n = shift;
  my $shellval = my $pid = `ps -ef | grep 'ss_gearman_event_worker.pl' | grep -v grep | awk '{print \$2}'`;
  system("kill -9 $pid"); 
}

sub init_EventWorker {  # I am not excited about running these scripts as root user commanded by the http server app but its an acceptable risk for an internally hosted system
  my $n = shift;
  system('perl ss_gearman_event_worker.pl &');
}

 ###########################
sub checkstat_ReputationWorker {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_gearman_reputation_worker.pl" | grep -v grep | wc -l`;
  if ($shellval >= 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}


sub kill_ReputationWorker {
  my $n = shift;
  
  my $shellval = my $pid = `ps -ef | grep 'ss_gearman_reputation_worker.pl' | grep -v grep | awk '{print \$2}'`;
  system("kill -9 $pid"); 
}

sub init_ReputationWorker {  # I am not excited about running these scripts as root user commanded by the http server app but its an acceptable risk for an internally hosted system
  my $n = shift;
  system('perl ss_gearman_reputation_worker.pl &');
}

  #########################

sub checkstat_rflowRcvr {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_Rflow_rcvrd.pl" | grep -v grep | wc -l`;
  if ($shellval >= 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}

sub init_FlowWorker {  # I am not ecxited about running these scripts as root user commanded by the http server app but its an acceptable risk for an internally hosted system
  my $n = shift;
  system('perl ss_Rflow_rcvrd.pl &');
}




sub kill_FlowWorker {
  my $n = shift;
  my $shellval = my $pid = `ps -ef | grep 'ss_Rflow_rcvrd.pl' | grep -v grep | awk '{print \$2}'`;
  system("kill -9 $pid"); 
}

############################

sub checkstat_dailyreporter {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_daily_reporter.pl" | grep -v grep | wc -l`;
  if ($shellval >= 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}

sub init_DailyWorker {  # I am not ecxited about running these scripts as root user commanded by the http server app but its an acceptable risk for an internally hosted system
  my $n = shift;
  system('perl ss_daily_reporter.pl &');
}

sub kill_DailyWorker {
  my $n = shift;
  my $shellval = my $pid = `ps -ef | grep 'ss_daily_reporter.pl' | grep -v grep | awk '{print \$2}'`;
  system("kill -9 $pid"); 
}


#######################################


sub checkstat_deltabytesalerter {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_deltabytes_alerter.pl" | grep -v grep | wc -l`;
  if ($shellval >= 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}

sub init_deltabytesalerter {  # I am not ecxited about running these scripts as root user commanded by the http server app but its an acceptable risk for an internally hosted system
  my $n = shift;
  system('perl ss_deltabytes_alerter.pl &');
}

sub kill_deltabytesalerter {
  my $n = shift;
  my $shellval = my $pid = `ps -ef | grep 'ss_deltabytes_alerter.pl' | grep -v grep | awk '{print \$2}'`;
  system("kill -9 $pid"); 
}


#######################################

sub checkstat_watcherreporter {
  my $n = shift;
  my $retval;
  my $shellval = `ps aux | grep -w "ss_watcher_worker.pl" | grep -v grep | wc -l`;
  if ($shellval >= 1) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}

sub init_WatcherWorker {  # I am not ecxited about running these scripts as root user commanded by the http server app but its an acceptable risk for an internally hosted system
  my $n = shift;
  system('perl ss_watcher_worker.pl &');
}



sub kill_WatcherWorker {
  my $n = shift;
  my $shellval = my $pid = `ps -ef | grep 'ss_watcher_worker.pl' | grep -v grep | awk '{print \$2}'`;
  system("kill -9 $pid"); 
}

#######################################


sub checkstat_gearmand {
  my $n = shift;
  my $retval;
  my $shellval = `ps cax | grep gearmand`;
  if ($shellval) {  $retval = "Running";} else {$retval = "Stopped";};
  return $retval 
}


sub sanitize_input {
    
    my ($dirty_invar) = @_;
    $dirty_invar =~ s/([;<>\*`&\$!#\(\)\[\]\{\}:'"])//g; # Lets Only allow | and . 
    $dirty_invar =~ s/[a-z]//gi; # Allow Integers
    my $sanitized_output = $dirty_invar;
    return $sanitized_output;
  
  }


sub sanitize_hostnames {
    
    my ($dirty_invar) = @_;
     $dirty_invar = substr($dirty_invar, 0,18); # Lets only allow a manageable size for hostnames
     $dirty_invar =~ s/[^a-zA-Z0-9]//g; # Lets Only allow numbers and letters for hostnames
    my $sanitized_output = $dirty_invar;
    return $sanitized_output;
  
  }



sub sanitize_numbers_only{
    
    my ($dirty_invar) = @_;
     $dirty_invar =~ s/[^0-9]//g; # Lets Only allow numbers in these strings
    my $sanitized_output = $dirty_invar;
    return $sanitized_output;
  
  }


## Debug Logging when Needed 
# app->log( Mojo::Log->new( path => '/home/{USERNAME}/netflow/running/mojolog', level => 'debug' ) );

app->start;





__DATA__

%# ##### A Very Basic HTML Landing Page - should be compatible with all browsers #############

@@ index.html.ep
<!DOCTYPE html>
<HTML>
<link href="/favicon-16x16.png" rel="icon" type="image/x-icon" />
<HEAD>
   <TITLE>Sockets Surveyor V1.0.0</TITLE>
%= t h1 => 'login'
</HEAD>
  <BODY BGCOLOR="BLACK" LINK="#0000BB">
   <CENTER><IMG src="/SocketsSurveyor.jpg" style="width:30px;height:30px;"><FONT SIZE=5 COLOR="CCFF66" FACE="ARIAL"><B> 
   Sockets Surveyor V1 
  </B></FONT></CENTER>
  <CENTER><FONT SIZE=-3 FACE="ARIAL" COLOR="DARKGREEN"><B>
   Courtesy Mollensoft Software </B></FONT></CENTER><p>
   <CENTER>
       <FONT SIZE=3 COLOR="WHITE" FACE="ARIAL">Enhancing Visibility of Your Internal Cyberspace! <P> </FONT><FONT SIZE=3 COLOR="LIGHTBLUE" FACE="ARIAL">Login To Access The <%= link_to 'Control Panel', '/adminpage' %></p> </FONT>
   <CENTER>

    % if (flash('error')) {
      <h2 style="color:red"><%= flash('error') %></h2>
    % }
    %= form_for login => (method => 'post') => begin
    <FONT SIZE=-1 FACE="ARIAL" COLOR="WHITE">username: <%= text_field 'username' %><p>
    password: <%= password_field 'password' %> <p>
    %= submit_button 'log in'
    %= end



%# ##### Admin page ##################################################


@@ adminpage.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Control Panel</h2>
				<p>This Page shows running services and Host Details Used by Sockets Surveyor System and future controls will be accessible here <p>
        If you are already logged in or session is still valid this is the default landing page. <p> <strong><%= $cmd_warning %></strong><p>


                                        <table>
                                          </tr>
                                           <tr>
                                            <td>Server Host </td>
                                            <td>Hostname:<%= $local_hostname %> - IpAddress:<%= $local_ip %> </td>
                                          </tr>
                                            <tr>
                                            <td>Event Workers </td>
                                            <td><%== $EventWorker_status %> </td>
                                          </tr>
                                          <tr>
                                            <td>Flow Receiver</td>
                                            <td><%== $RflowListner_status %> </td>
                                          </tr>
                                           <tr>
                                            <td>Watcher Worker </td>
                                            <td><%== $checkstat_watcherreporter  %> </td>
                                          </tr>
                                           <tr>
                                            <td>Reputation Worker</td>
                                            <td><%== $reputation_workstat %> </td>
                                          </tr>
                                           <tr>
                                            <td>DeltaBytes Alerter</td>
                                            <td><%== $checkstat_deltabytesalerter  %> </td>
                                          </tr>
                                          <td>Daily Report Worker</td>
                                            <td><%== $checkstat_dailyreporter %> </td>
                                          </tr>                                          <tr>
                                            <td>Gearmand</td>
                                            <td><%=$gearmand_status %> </td>
                                          </tr>
                                          <tr>
                                            <td>Workers</td>
                                            <td><pre><%= $gman_workstat %> </td>
                                          </tr>
                                        </table>

				
        <br> Note: The Control panel will only start a single Event Worker - if you Need More than one (unlikely but possible at times) start them manually.<br>
        <br> <font color="red"> Warning: Starting and Stopping Processes Via this Web Interface is a Developmental feature, there may be unexpected results -
        Its Best to Run Event Workers from a command line </font><br>
        </section>
		</div>
<%== $navigation_page_footer %>




%# ##### Help Docs ##################################################





@@ helpdocs.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Help Docs</h2>
				<p>This Page shows Help, Documentation and Tips
                                
         <h1><IMG src="/SocketsSurveyorOverviewV1.png" style="width:50%;height:50%;" > </h1>

            <P>                                            
               
               
           <strong><em> Note 1: Updating the GeoLite Free Database <br> </em></strong>
            
            Download the current Geolib from Maxmind like this: <br>
            
            curl -o GeoLite2-City.tar.gz http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz <br>
            
            where GeoLite2-City.tar.gz is the output file name <br>
            
            now decompress and untar the file using tar -xzf GeoLite2-City.tar.gz and you will see a directory created named GeoLite2-City_YYYYMMDD <br>
            
            Copy the GeoLite2-City.mmdb  into the working directory /geolibs/current folder using a command like  <br>
            
            " mv GeoLite2-City.mmdb ../current " this will update the currently used geolib database/GeoLite2-City <br>
            
            <P>
            
            <strong><em> Note 2: Changing the Password for the default username "analyst"  <br></em></strong>
            
            Click on the "Add/Update Account" Link in the Navigation Panel <br>
            
            Type in a new Password into both text boxes and then click the "Submit" Button to save the new Password. <br>
            
            When you log out the new Password will take affect upon logging in again. <br>
            
            If the passwords that you entered into both text boxes do not match, the password will not be changed and you will see a warning on the page when this occurs <br>
            
            
            
            



			</section>
		</div>
<%== $navigation_page_footer %>



%# ##### Detailed host Query ##################################################



@@ detailedhost.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Detailed Internal Host Event Reports</h2>
				<p><P> Select Internal Host To Run Detailed Event Report</p>
                              <table border="1">
                                <tr>
                                  <th>IP Address </th>
                                  <th>Hostname</th>
                                  <th>Run Detailed Host Report for the Specified Host</th>                                                
                                  </tr>
                                % foreach my $item (@$rows3) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %></td>
                                 <td>
                                 <%= link_to '[Last Hour]', =>  url_for( '/detailedhost' )->query( ip => $item->[0], time => 1, host => $item->[1] )%>
                                 <%= link_to '[Last 24 Hours]', =>  url_for( '/detailedhost' )->query( ip => $item->[0], time => 24 , host => $item->[1] )%>
                                 <%= link_to '[Last  7 Days]', =>  url_for( '/detailedhost' )->query( ip => $item->[0], time => 168, host => $item->[1]  )%>                                  
                                 <%= link_to '[Last 30 Days]', =>  url_for( '/detailedhost' )->query( ip => $item->[0], time => 720, host => $item->[1]  )%>
                                 <%= link_to '[Last 90 Days]', =>  url_for( '/detailedhost' )->query( ip => $item->[0], time => 2160 , host => $item->[1] )%>
                                 </td> </tr>
                                 
                                % }
                              </table>


% if ($resptype == 1 ) {


                                <br><br><a href="#Bottom100">Jump to Bottom 100 Destinations By Connection Count</a><p>
                                <a href="#OutboundBytes">Jump to Outbound Destinations By Bytes Count</a><p>

				<p><P> Top 100 Outbound Destinations for Internal Host: <%=$internalhost%> Last <%=$querytime%> Hours</p>
                              <table border="1">
                                <tr>
                                  <th>Internal Host </th>
                                  <th>Reputation</th>
                                  <th>Destination Ip Address</th>
                                  <th>Connection Count</th>
                                  <th>Destintation Hostname</th>
                                  <th>Destination Org</th>
                                  <th>NetName</th>
                                  <th>Survey Results</th>                                  
                                  </tr>
                                % foreach my $item (@$rows4) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %>
                                      </td> <td><%=$item->[2]%>
                                     <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[2]%>&action:Search=Search" target="_blank">[T]</a> 
                                     <a href="https://www.virustotal.com/#/ip-address/<%=$item->[2]%>" target="_blank">[V]</a>
                                     <a href="https://www.shodan.io/host/<%=$item->[2]%>" target="_blank">[S]</a>
                                     <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[2]%>" target="_blank">[A]</a>                                           
                                     <a href="/destdetail?ipaddress=<%=$item->[2]%>" target="_blank">[D]</a>                                                                                                                  
                                      </td><td><%=$item->[3] %></td> <td><%=$item->[4] %></td><td><%=$item->[5] %></td><td><%=$item->[6] %></td> <td><%=$item->[7] %></td>
                                  </tr>
                                % }
                              </table>

                                 <h2 id="Bottom100">Bottom 100 Dest By Connection Count</h2>
				<p><P> Bottom 100 Outbound Destinations for Internal Host: <%=$internalhost%> Last <%=$querytime%> Hours</p>
                              <table border="1">
                                <tr>
                                  <th>Internal Host </th>
                                  <th>Reputation</th>
                                  <th>Destination Ip Address</th>
                                  <th>Connection Count</th>
                                  <th>Destintation Hostname</th>
                                  <th>Destination Org</th>
                                  <th>Net Name</th>                                  
                                  <th>Survey Results</th>                                  
                                  </tr>
                                  
                                %foreach my $item (@$rows5) {
                                  <tr>
                                      <td><%=$item->[0] %></td>  <td><%=$item->[1] %></td><td><%=$item->[2]%>
                                     <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[2]%>&action:Search=Search" target="_blank">[T]</a> 
                                     <a href="https://www.virustotal.com/#/ip-address/<%=$item->[2]%>" target="_blank">[V]</a>
                                     <a href="https://www.shodan.io/host/<%=$item->[2]%>" target="_blank">[S]</a>
                                     <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[2]%>" target="_blank">[A]</a>                                          
                                     <a href="/destdetail?ipaddress=<%=$item->[2]%>" target="_blank">[D]</a>                                                                                                                  
                                      </td><td><%=$item->[3] %></td> <td><%=$item->[4] %></td><td><%=$item->[5] %></td><td><%=$item->[6] %></td> <td><%=$item->[7] %></td>
                                  </tr>
                                % }
                              </table>

                                 <h2 id="OutboundBytes">Outbound By bytes</h2>
				<p><P> Outbound Bytes Report for Internal Host: <%=$internalhost%> Last <%=$querytime%> Hours</p>
                              <table border="1">
                                <tr>
                                  <th>Byte Count </th>
                                  <th>Reputation</th>
                                  <th>Destination Ip Address</th>
                                  <th>Destination Hostname</th>
                                  <th>Destination Org</th>
                                  <th>Net Name</th>                                  
                                  <th>Survey Results</th>
                                  </tr>
                                % foreach my $item (@$rows6) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %></td> <td><%=$item->[2]%>
                                     <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[2]%>&action:Search=Search" target="_blank">[T]</a> 
                                     <a href="https://www.virustotal.com/#/ip-address/<%=$item->[2]%>" target="_blank">[V]</a>
                                     <a href="https://www.shodan.io/host/<%=$item->[2]%>" target="_blank">[S]</a>
                                     <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[2]%>" target="_blank">[A]</a>                                           
                                     <a href="/destdetail?ipaddress=<%=$item->[2]%>" target="_blank">[D]</a>                                                                                                                  
                                      </td><td><%=$item->[3] %></td> <td><%=$item->[4] %></td> <td><%=$item->[5] %></td><td><%=$item->[6] %></td>
                                  </tr>
                                 
                                % }
                              </table>

%}

			</section>
		</div>
<%== $navigation_page_footer %>





%# ##### Destination Details ##################################################







@@ destdetail.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Destination Query Page (Warning these Reports can be Slow!)</h2>
				<p><P> <B> Please enter a destination Ip adress to query </B></p>

         % if (length $respmesg > 1) {
            	 <B>   <%==$respmesg%> </B><p>
         % }

      <form name="f1" action="destdetail">
  <p>IpAddress: <input name="ipaddress" type="text">  
  <input type="submit" value="Submit">
  <div id="result"></div>
</form>

% if ($resptype == 2 ) {
                              
              <P><B> Running Query on Ip Address: <%= $qip %>         </B><p>      
                              
                              <table border="1">
                                <tr>
                                  <th>First Seen</th>
                                  <th>Last Seen</th>
                                  <th>Dest Ip Address</th>                                  
                                  <th>Dest Hostname</th>
                                  <th>Dest Region</th>
                                  <th>Dest Country</th>
                                  <th>Dest Org</th>
                                  <th>Net Name</th>                                  
                                  <th>Reputation</th>                                  
                                  </tr>
                                % foreach my $item (@$rows1) {
                                  <tr>
                                     <td><%=$firstseen %></td><td><%=$lastseen %></td>  <td><%=$item->[0] %>
                                     <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[0]%>&action:Search=Search" target="_blank">[T]</a> 
                                     <a href="https://www.virustotal.com/#/ip-address/<%=$item->[0]%>" target="_blank">[V]</a>
                                     <a href="https://www.shodan.io/host/<%=$item->[0]%>" target="_blank">[S]</a>
                                     <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[0]%>" target="_blank">[A]</a>      
                                     </td> <td><%=$item->[1] %></td><td><%=$item->[2] %></td> <td><%=$item->[3] %></td> <td><%=$item->[4] %></td><td><%=$item->[5] %></td><td><%=$item->[6] %></td></tr>
                                 
                                % }
                              </table>                             
          <P><P><B> Internal Hosts that have contacted this Destination  </B><p>      
                              <table border="1">
                                <tr>
                                  <th>Internal Host Name </th>
                                  <th>Internal IP Address</th>
                                  </tr>
                                % foreach my $item2 (@$rows2) {
                                  <tr><td><%=$item2->[0] %></td> <td><%=$item2->[1] %></td></tr>
                                % }
                              </table>                             

 % }                              
                   
<P>
<div id="exechistory">
<h1>Run Ip Address History Report</h1>
<button type="button" onclick="loadDoc()">Run Connection History</button>
</div>        
<script>
function loadDoc() {
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      document.getElementById("exechistory").innerHTML =
      this.responseText;
    }
  };
  xhttp.open("POST", "exechistory?ip=<%=$qip%>", true);
  xhttp.send();
}
</script>               
                   
                              
			</section>
		</div>
    
 % if ($resptype2 == 3 ) {
  <B>   <%==$respmesg2%> </B><p> 
  % }  
  
<%== $navigation_page_footer %>







%# ##### Summary View ##################################################








@@ summaryview.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Summary View of All Internal Hosts (Warning this Report is Slow!)</h2>


                            <div id="exechistory">
                                 Loading Please Wait....
                                <img src="Loading_icon.gif" alt="Searching" />
                            
                            </div>

                            <script type="text/javascript">
                            function loadDoc() {
                              var xhttp = new XMLHttpRequest();
                              xhttp.onreadystatechange = function() {
                                if (this.readyState == 4 && this.status == 200) {
                                  document.getElementById("exechistory").innerHTML =
                                  this.responseText;
                                }
                              };
                              xhttp.open("GET", "fetchsummaryview", true);
                              xhttp.send();
                            }
                             window.onload = loadDoc;
                            </script>           
    
			</section>
		</div>
<%== $navigation_page_footer %>







%# ##### Graph All-at-once ##################################################






@@ graphviewall.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Summary Graph View</h2>
<canvas id="myChart" width="undefined" height="undefined"></canvas>
<script>
var ctx = document.getElementById("myChart").getContext('2d');
var myChart = new Chart(ctx, {
    type: 'bar',
    data: {
<%==$chart_labels_str%>
      datasets: [
        {
          label: "Events",
<%==$chart_colors_str%>
<%==$chart_values_str%>
        }
      ]
    },
    options: {
      legend: { display: false },
      title: {
        display: true,
        text: 'Total Events Per Day - Spanning Last 7 days'
      }
    }
});
</script>
<BR><BR>
<canvas id="myChart2" width="undefined" height="undefined"></canvas>
<script>
var ctx = document.getElementById("myChart2").getContext('2d');
var myChart2 = new Chart(ctx, {
    type: 'bar',
    data: {
<%==$chart_labels_str2%>
      datasets: [
        {
          label: "Events",
<%==$chart_colors_str2%>
<%==$chart_values_str2%>
        }
      ]
    },
    options: {
      legend: { display: false },
      title: {
        display: true,
        text: 'Total Events Per Day - Spanning Last 30 days'
      }
    }
});
</script>
			</section>
		</div>
<%== $navigation_page_footer %>



%# ##### GraphView By Device ##################################################





@@ graphviewdevice.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Summary Graph View</h2>

% my $ctr++;
% foreach my $ritem (@$records) {
% $ctr++;
% my $name = $ritem->{"name"} ;
% my $labels = $ritem->{"labels"};
% my $values = $ritem->{"values"}; 
% my $colors = $ritem->{"colors"};  

<canvas id="myChart<%==$ctr%>" width="undefined" height="undefined"></canvas>
<script>
var ctx = document.getElementById("myChart<%==$ctr%>").getContext('2d');
var myChart = new Chart(ctx, {
    type: 'bar',
    data: {
<%==$labels%>
      datasets: [
        {
          label: "Events",
<%==$colors%>
<%==$values%>
        }
      ]
    },
    options: {
      legend: { display: false },
      title: {
        display: true,
        fontSize: 16,
        text: 'Total Events Per Day For Device: <%==$name%> - Spanning Last 7 days' 
      }
    }
});
</script>

<BR><BR>
%};

% foreach my $ritem2 (@$records2) {
% $ctr++;
% my $name2 = $ritem2->{"name"} ;
% my $labels2 = $ritem2->{"labels"};
% my $values2 = $ritem2->{"values"}; 
% my $colors2 = $ritem2->{"colors"};  

<canvas id="myChart<%==$ctr%>" width="undefined" height="undefined"></canvas>
<script>
var ctx = document.getElementById("myChart<%==$ctr%>").getContext('2d');
var myChart = new Chart(ctx, {
    type: 'bar',
    data: {
<%==$labels2%>
      datasets: [
        {
          label: "Events",
<%==$colors2%>
<%==$values2%>
        }
      ]
    },
    options: {
      legend: { display: false },
      title: {
        display: true,
        fontSize: 16,        
        text: 'Total Events Per Day For Device: <%==$name2%> - Spanning Last 30 days' 
      }
    }
});
</script>

<BR><BR>
%};

			</section>
		</div>
<%== $navigation_page_footer %>





%# ##### Reputation Report ##################################################





@@ reputationrpt.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Detailed Destination Reputation Reports</h2>
				<p><P> Select Host To Run Detailed Reputation Report</p>
                              <table border="1">
                                <tr>
                                  <th>IP Address </th>
                                  <th>Hostname</th>
                                  <th>Run Detailed Reputation Report for the Specified Host</th>                                                
                                  </tr>
                                % foreach my $item (@$rows3) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %></td>
                                 <td>
                                 <%= link_to '[Last Hour]', =>  url_for( '/reputationrpt' )->query( ip => $item->[0], time => 1, host => $item->[1] )%>
                                 <%= link_to '[Last 24 Hours]', =>  url_for( '/reputationrpt' )->query( ip => $item->[0], time => 24 , host => $item->[1] )%>
                                 <%= link_to '[Last  7 Days]', =>  url_for( '/reputationrpt' )->query( ip => $item->[0], time => 168, host => $item->[1]  )%>                                  
                                 <%= link_to '[Last 30 Days]', =>  url_for( '/reputationrpt' )->query( ip => $item->[0], time => 720, host => $item->[1]  )%>
                                 <%= link_to '[Last 90 Days]', =>  url_for( '/reputationrpt' )->query( ip => $item->[0], time => 2160 , host => $item->[1] )%>
                                 </td> </tr>
                                 
                                % }
                              </table>


% if ($resptype == 1 ) {

				<p><P> Top 100 Outbound Connections to IP addresses with Bad Reputation (3) For Internal Host: <%=$internalhost%> Last <%=$querytime%> Hours</p>
                              <table border="1">
                                <tr>
                                  <th>Internal Host </th>
                                  <th>Reputation</th>
                                  <th>Destination Ip Address</th>
                                  <th>Connection Count</th>
                                  <th>Destintation Hostname</th>
                                  <th>Destination Org</th>
                                  <th>Net Name</th>
                                  <th>Survey Results</th>      
                                  </tr>

                                % foreach my $item (@$rows4) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %>
                                      </td> <td><%=$item->[2]%>
                                      <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[2]%>&action:Search=Search" target="_blank">[T]</a> 
                                      <a href="https://www.virustotal.com/#/ip-address/<%=$item->[2]%>" target="_blank">[V]</a>
                                      <a href="/destdetail?ipaddress=<%=$item->[2]%>" target="_blank">[D]</a>
                                      <a href="https://www.shodan.io/host/<%=$item->[2]%>" target="_blank">[S]</a>
                                      <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[2]%>" target="_blank">[A]</a>      
                                      </td><td><%=$item->[3] %></td> <td><%=$item->[4] %></td><td><%=$item->[5] %></td><td><%=$item->[6] %></td>
                                 <td>
                                 </td> </tr>
                                % }

                              </table>
%}


			</section>
		</div>
<%== $navigation_page_footer %>










%# ##### Custom Dates ##################################################










@@ custom.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Custom Queries</h2>
				<p>This Page Enables You To Perform Customized Date Time Queries of the Host Connection Event Data and Analytics
                                
				<p><P> <B> Please enter a Starting and Ending Date-Time to query within to query (Example: 2018-05-17 11:00:00 and 2018-05-17 12:00:00) </B></p>
        
         % if ($resptype == 1 ) {
            	 <B>   <%==$respmesg%> </B><p>
         % }
                             

  <form name="f1" action="custom">
 <p>Starting DateTime: <input name="startdatetime" type="text">  <p>Ending DateTime: <input name="enddatetime" type="text">  <p>  
  <input type="submit" value="Submit">
  <div id="result"></div>
  </form>
                            
       
      % if (my $table_str = stash 'table_str') {                                  
          <%==$table_str%> 
      % }


			</section>
		</div>
<%== $navigation_page_footer %>






%# ##### Report View ##################################################






@@ reportview.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>List of Historical Text Reports</h2>
				<p>This page record copies of the the contents from all email tipper reports as an historical archive 
                                
				<p>
          % if (my $report_str = stash 'report_str') {                                  
              <%==$report_str%> 
          % }                          
                 
			</section>
		</div>
<%== $navigation_page_footer %>




%# ##### DEST Ports Report ##################################################




@@ dstportsrpt.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Destination Ports Connection Reports</h2>
				<p><P> Select Host To Run Detailed Destination Ports Report</p>
                              <table border="1">
                                <tr>
                                  <th>IP Address </th>
                                  <th>Hostname</th>
                                  <th>Run Destination Ports Report for the Specified Host</th>                                                
                                  </tr>
                                % foreach my $item (@$rows3) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %></td>
                                 <td>
                                 <%= link_to '[Last Hour]', =>  url_for( '/dstportsrpt' )->query( ip => $item->[0], time => 1, host => $item->[1] )%>
                                 <%= link_to '[Last 24 Hours]', =>  url_for( '/dstportsrpt' )->query( ip => $item->[0], time => 24 , host => $item->[1] )%>
                                 <%= link_to '[Last  7 Days]', =>  url_for( '/dstportsrpt' )->query( ip => $item->[0], time => 168, host => $item->[1]  )%>                                  
                                 <%= link_to '[Last 30 Days]', =>  url_for( '/dstportsrpt' )->query( ip => $item->[0], time => 720, host => $item->[1]  )%>
                                 <%= link_to '[Last 90 Days]', =>  url_for( '/dstportsrpt' )->query( ip => $item->[0], time => 2160 , host => $item->[1] )%>
                                 </td> </tr>
                                 
                                % }
                              </table>
% if ($resptype == 1 ) {

				<p><P> Destination Connection Ports For Internal Host: <%=$internalhost%> Last <%=$querytime%> Hour(s)</p>
                              <table border="1">
                                <tr>
                                  <th>Count </th>
                                  <th>Dest Port</th>
                                  <th>Protocol</th>
                                  <th>Dest Hostname</th>
                                  <th>Destintation Org</th>
                                  <th>Net Name</th>                                  
                                  <th>Destination IP</th>                            
                                  </tr>

                                % foreach my $item (@$rows4) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %>
                                      </td> <td><%=$item->[2]%>
                                                                                                                                                       
                                      </td><td><%=$item->[3] %></td> <td><%=$item->[4] %></td><td><%=$item->[5] %><td><%=$item->[6] %>
                                      <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[6]%>&action:Search=Search" target="_blank">[T]</a> 
                                      <a href="https://www.virustotal.com/#/ip-address/<%=$item->[6]%>" target="_blank">[V]</a>
                                      <a href="/destdetail?ipaddress=<%=$item->[6]%>" target="_blank">[D]</a>
                                      <a href="https://www.shodan.io/host/<%=$item->[6]%>" target="_blank">[S]</a>
                                      <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[6]%>" target="_blank">[A]</a>                                       </td> </tr>
                                % }

                              </table>
%}
			</section>
		</div>
<%== $navigation_page_footer %>



%# ##### ZERODAYS Report ##################################################




@@ zerodaysrpt.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Zero Days Contact Reports</h2>
				<p>This Report Lists New Destination Addresses Contacted by the Selected Internal Host within the Selected Time Window [Internal Contacted Destination For the First Time in this Timeframe]</p>
                              <table border="1">
                                <tr>
                                  <th>IP Address </th>
                                  <th>Hostname</th>
                                  <th>Date Time Range of New Contacts</th>                                                
                                  </tr>
                                % foreach my $item (@$rows3) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %></td>
                                 <td>
                                 <%= link_to '[Last Hour]', =>  url_for( '/zerodays' )->query( ip => $item->[0], time => 1, host => $item->[1] )%>
                                 <%= link_to '[Last 24 Hours]', =>  url_for( '/zerodays' )->query( ip => $item->[0], time => 24 , host => $item->[1] )%>
                                 <%= link_to '[Last  7 Days]', =>  url_for( '/zerodays' )->query( ip => $item->[0], time => 168, host => $item->[1]  )%>                                  
                                 <%= link_to '[Last 30 Days]', =>  url_for( '/zerodays' )->query( ip => $item->[0], time => 720, host => $item->[1]  )%>
                                 <%= link_to '[Last 90 Days]', =>  url_for( '/zerodays' )->query( ip => $item->[0], time => 2160 , host => $item->[1] )%>
                                 </td> </tr>
                                 
                                % }
                              </table>
% if ($resptype == 1 ) {

				<p><P> New Destination Contacts From Internal Host: <%=$internalhost%> Within Last <%=$querytime%> Hour(s) Sorted From Highest-to-Lowest Count of Contacts within the Time Window Selected [<%=$rowcount %> Items]
        
        </p>
                              <table border="1">
                                <tr>
                                  <th>Host </th>
                                  <th>Dest Reputation</th>
                                  <th>Date Created</th>
                                  <th>Destination IP</th>
                                  <th>Count</th>
                                  <th>Bytes</th>                                  
                                  <th>Destination Hostname</th>                            
                                  <th>Destination Org</th>                                  
                                  <th>Network Name</th>                            
                                  <th>Survey Results</th>    
                                  </tr>

                                % foreach my $item (@$rows4) {
                                   <tr>
                                      <td><%=$item->[0] %></td>
                                      <td><%=$item->[1] %></td> 
                                      <td><%=$item->[2]%></td> 
                                      <td><%=$item->[3] %>
                                      <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[3]%>&action:Search=Search" target="_blank">[T]</a> 
                                      <a href="https://www.virustotal.com/#/ip-address/<%=$item->[3]%>" target="_blank">[V]</a>
                                      <a href="/destdetail?ipaddress=<%=$item->[3]%>" target="_blank">[D]</a>
                                      <a href="https://www.shodan.io/host/<%=$item->[3]%>" target="_blank">[S]</a>
                                      <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[3]%>" target="_blank">[A]</a>                                      
                                      </td>
                                      <td><%=$item->[4] %></td>
                                      <td><%=$item->[5] %></td>
                                      <td><%=$item->[6] %></td>
                                      <td><%=$item->[7] %></td>
                                      <td><%=$item->[8] %></td>
                                      <td><%=$item->[9] %></td>
                                      </tr>
                                % }

                              </table>
%}
			</section>
		</div>
<%== $navigation_page_footer %>




%# ##### Change PassWord ##################################################


@@ changepassword.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2>Update/Change Account Login Details</h2>
				<p>This Page Enables You To Change the Current Password The Analyst User account: analyst
                                
				<p><P> <B> Please enter new password for the System User: analyst </B></p>
        
        <%= $responsemsg %> <p>
                             

  <form name="f1" action="changepassword">
 <p>   <p>New Password: <input name="password1" type="password">  <p>  <p>Password Again: <input name="password2" type="password">
 <p>
  <input type="submit" value="Submit">
  <div id="result"></div>
  </form>
                            
       
			</section>
		</div>
<%== $navigation_page_footer %>






%# ##### MODIFY INTERNAL HOST LIST ##################################################




@@ modhosts.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
		
                
                
		<div id="wrapper">
			<section id="content2">
				<h2>Add or Remove Internal Hosts For Tracking</h2>
				<p>This Page Enables You To Add or Remove Internal Hosts You Wish to Track Packets For 
                
                      % if (my $responsemsg = stash 'responsemsg') {                                  
                        <%==$responsemsg%> 
                         % }
                     
  <form name="f1" action="modhosts"><input type="hidden" name="action" value="2">
 <p>   <p>New HostName: <input name="newhostname" type="text">  IP Address: <input name="newipaddress" type="text">
  <input type="submit" value="Add New Host">  
  <div id="result"></div>
  </form>
                      
       
			</section>
		</div>                
                
                   <P>   
                
                              <table border="1">
                                <tr>
                                  <th>IP Address </th>
                                  <th>Hostname</th>
                                  <th>Date Time Range of New Contacts</th>                                                
                                  </tr>
                                % foreach my $item (@$rows3) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %></td>
                                 <td>
                                 <%= link_to '[Remove Host]', =>  url_for( '/modhosts' )->query( ip => $item->[0], action => 1 )%>
                                  </tr>
                                 
                                % }
                              </table>


			</section>
		</div>
<%== $navigation_page_footer %>




%# ##### Identify HTTP Dest Flow Outliers by Standard Deviation of 5 or greater ##################################################



@@ stdev.html.ep
<%== $web_page_header %>
		<div id="wrapper">
			<section id="content">
				<h2> HTTP Destination Outlier Query </h2>
				<p><P> Show Events Where Dest Port was 80 and 443 and Standard Deviation > 5 Query</p>
                              <table border="1">
                                <tr>
                                  <th>IP Address </th>
                                  <th>Hostname</th>
                                  <th>Run Detailed Std Deviation Report for the Specified Host</th>                                                
                                  </tr>
                                % foreach my $item (@$rows3) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %></td>
                                 <td>
                                 <%= link_to '[Last Hour]', =>  url_for( '/stdev' )->query( ip => $item->[0], time => 1, host => $item->[1] )%>
                                 <%= link_to '[Last 24 Hours]', =>  url_for( '/stdev' )->query( ip => $item->[0], time => 24 , host => $item->[1] )%>
                                 <%= link_to '[Last  7 Days]', =>  url_for( '/stdev' )->query( ip => $item->[0], time => 168, host => $item->[1]  )%>                                  
                                 <%= link_to '[Last 30 Days]', =>  url_for( '/stdev' )->query( ip => $item->[0], time => 720, host => $item->[1]  )%>
                                 <%= link_to '[Last 90 Days]', =>  url_for( '/stdev' )->query( ip => $item->[0], time => 2160 , host => $item->[1] )%>
                                 </td> </tr>
                                 
                                % }
                              </table>


% if ($resptype == 1 ) {

				<p><P> HTTP Outbound Events Where Flow Byte Count > 5 Standard Deviations Above the Average Byte Count For Internal Host: <%=$internalhost%> Period Last: <%=$querytime%> Hours [ 5 X STDDevs Bytes: <%=$bytesX5%>]</p>
                              <table border="1">
                                <tr>
                                  <th>Bytes </th>
                                  <th>Event Date</th>
                                  <th>Internal Host</th>
                                  <th>Reputation</th>
                                  <th>Destintation Address</th>
                                  <th>Destination Hostname</th>
                                  <th>Destination Org</th>
                                  <th>Destination Net</th>                                  
                                  </tr>
                                % foreach my $item (@$rows4) {
                                  <tr>
                                      <td><%=$item->[0] %></td> <td><%=$item->[1] %>
                                      </td> <td><%=$item->[2]%></td>
                                      <td><%=$item->[3] %></td> <td><%=$item->[4] %>
                                     <a href="https://www.talosintelligence.com/reputation_center/lookup?search=<%=$item->[4]%>&action:Search=Search" target="_blank">[T]</a> 
                                     <a href="https://www.virustotal.com/#/ip-address/<%=$item->[4]%>" target="_blank">[V]</a>
                                     <a href="https://www.shodan.io/host/<%=$item->[4]%>" target="_blank">[S]</a>
                                     <a href="https://otx.alienvault.com/indicator/ip/<%=$item->[4]%>" target="_blank">[A]</a>                                           
                                     <a href="/destdetail?ipaddress=<%=$item->[4]%>" target="_blank">[D]</a>                                                                                                                  
                                      </td>                                      
                                      </td><td><%=$item->[5] %></td><td><%=$item->[6] %></td> <td><%=$item->[7] %></td>
                                  </tr>
                                % }
                              </table>


%}

			</section>
		</div>
<%== $navigation_page_footer %>





