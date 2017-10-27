#!/usr/local/bin/perl
use strict;
use warnings FATAL => 'all';
#use utf8;
#use POSIX qw(setsid setuid strftime :signal_h);
use Getopt::Long;
use Server;

my $server;
my ($BIND_ADDR, $SERVER_PORT, $CLIENT_PORT, $MIRROR, $DHCP_SERVER_ID, $THREADS_COUNT, $DBDATASOURCE, $DBLOGIN, $DBPASS, $PIDFILE, $DEBUG, $DAEMON);

&start();

# this keeps the program alive or something after exec'ing perl scripts
END{}
BEGIN{}
{
    no warnings; *CORE::GLOBAL::exit = sub {die "fakeexit\nrc=" . shift() . "\n";};
};
eval q{exit};
if ($@) {exit unless $@ =~ /^fakeexit/;};

sub start {
    if ($#ARGV == - 1) {usage();}
    
    $server = Server->new();
    GetOptions(
        'b=s'   => \$BIND_ADDR,
        'sp:i'  => \$SERVER_PORT,
        'cp:i'  => \$CLIENT_PORT,
        'id=s'  => \$DHCP_SERVER_ID,
        'm=s'   => \$MIRROR,
        't:i'   => \$THREADS_COUNT,
        'dbs=s' => \$DBDATASOURCE,
        'dbl=s' => \$DBLOGIN,
        'dbp=s' => \$DBPASS,
        'P:s'   => \$PIDFILE,
        'v:i'   => \$DEBUG,
        'd'     => \$DAEMON,
    );

    $SIG{INT} = $SIG{TERM} = $SIG{HUP} = sub {$server->signal_handler();};
    $SIG{PIPE} = 'IGNORE';

    if (defined($DAEMON)) {
        $DEBUG = 0;
    }

    $server->set('DEBUG', $DEBUG);
    $server->set('BIND_ADDR', $BIND_ADDR);
    $server->set('SERVER_PORT', $SERVER_PORT);
    $server->set('CLIENT_PORT', $CLIENT_PORT);
    $server->set('DHCP_SERVER_ID', $DHCP_SERVER_ID);
    $server->set('MIRROR', $MIRROR);
    $server->set('DBDATASOURCE', $DBDATASOURCE);
    $server->set('DBLOGIN', $DBLOGIN);
    $server->set('DBPASS', $DBPASS);
    $server->set('THREADS_COUNT', $THREADS_COUNT);
    $server->set('PIDFILE', $PIDFILE);
    $server->set('DAEMON', $DAEMON);
}

sub usage {
    print "Usage: dhcpd [options]\n\n";
    print " -b <ip>		ip address to bind (def: 0.0.0.0)\n";
    print " -sp <port>		port bind (def: 67)\n";
    print " -cp <port>		port to send reply directly to client (def: 68)\n";
    print " -id <ip>		ip addr DHCP server ID, REQUIRED!, MUST be real IP of server\n";
    print " -m <ip>		ip address to mirror all packets on 67 port\n";
    print " -t <threads>		number of thread, recomended: CPU cores * 2, (default 4)\n";
    print " -dbs			database data source: DriverName:database=database_name;host=hostname;port=port\n";
    print " -dbl			data base login\n";
    print " -dbp			data base password\n";
    print " -P <path>		name of PID-file for spawned process\n";
    print " -v <level>		print debug info, levels: 1, 2 (def: off)\n";
    print " -d			daemon mode\n";

    exit;
}

$server->start();
