#!/usr/local/bin/perl
use strict;
use warnings FATAL => 'all';
#use utf8;
#use POSIX qw(setsid setuid strftime :signal_h);
use Getopt::Long;
use Server;

my $server;
my ($BIND_ADDR, $SERVER_PORT, $CLIENT_PORT, $MIRROR, $DHCP_SERVER_ID, $THREADS_COUNT, $DBDATASOURCE, $DBLOGIN, $DBPASS, $PIDFILE, $DEBUG, $DAEMON);

my $get_requested_data = "SELECT * FROM `clients`, `subnets` WHERE `clients`.`mac` = '\$mac' AND `clients`.`subnet_id` = `subnets`.`subnet_id` AND `subnets`.`gateway` = '\$ipaddr' LIMIT 1;";
my $get_requested_data_opt82 = "SELECT * FROM `subnets`, `ips` WHERE `subnets`.`vlan_id` = '\$dhcp_opt82_vlan_id' AND `subnets`.`type` = 'guest' AND `ips`.`lease_time` = '' LIMIT 1;";
my $get_routing = "SELECT `destination`, `mask` `gateway` FROM `subnets_routes` WHERE `subnet_id` = '\$_[2]' LIMIT 30;";
my $lease_offered = "UPDATE `ips` SET `mac` = '\$mac', `lease_time` = UNIX_TIMESTAMP()+3600 WHERE `ip` = '" . \$_[2]->yiaddr() . "';";
my $lease_nak = "";
my $lease_decline = "INSERT INTO `dhcp_log` (`created`,`client_mac`,`client_ip`,`gateway_ip`,`client_ident`,`requested_ip`,`hostname`, `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`, `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`) VALUES (NOW(),'\$mac','\$client_ip','\$gateway_ip','\$client_ident','\$requested_ip','\$hostname', '\$dhcp_vendor_class','\$dhcp_user_class','\$dhcp_opt82_chasis_id','\$dhcp_opt82_unit_id', '\$dhcp_opt82_port_id','\$dhcp_opt82_vlan_id','\$dhcp_opt82_subscriber_id');";
my $lease_release = "UPDATE `ips` SET `lease_time` = '', `mac` = NULL WHERE `mac` ='\$mac';";
my $lease_success = "UPDATE `ips` SET `lease_time` = UNIX_TIMESTAMP()+3600, `mac` ='\$mac' WHERE `ip` = (SELECT `ip` FROM `clients` WHERE `mac` = '\$mac' AND`subnet_id` = (SELECT `subnet_id` FROM `subnets` WHERE `vlan_id` = \$dhcp_opt82_vlan_id AND `type` != 'guest'));";
my $log_detailed = "INSERT INTO `dhcp_log` (`created`,`client_mac`,`client_ip`,`gateway_ip`,`client_ident`,`requested_ip`,`hostname`, `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`, `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`) VALUES (NOW(),'\$mac','\$client_ip','\$gateway_ip','\$client_ident','\$requested_ip','\$hostname', '\$dhcp_vendor_class','\$dhcp_user_class','\$dhcp_opt82_chasis_id','\$dhcp_opt82_unit_id', '\$dhcp_opt82_port_id','\$dhcp_opt82_vlan_id','\$dhcp_opt82_subscriber_id') ON DUPLICATE KEY UPDATE `client_ip` = '\$client_ip', `client_ident` = '\$client_ident', `requested_ip` = '\$requested_ip', `hostname` = '\$hostname', `dhcp_vendor_class` = '\$dhcp_vendor_class', `dhcp_user_class` = '\$dhcp_user_class', `gateway_ip` = if('\$gateway_ip' = '0.0.0.0', `gateway_ip`, '\$gateway_ip'), `dhcp_opt82_chasis_id` = if('\$dhcp_opt82_chasis_id' = '', `dhcp_opt82_chasis_id`, '\$dhcp_opt82_chasis_id'), `dhcp_opt82_unit_id` = if('\$dhcp_opt82_unit_id' = '', `dhcp_opt82_unit_id`, '\$dhcp_opt82_unit_id'), `dhcp_opt82_port_id` = if('\$dhcp_opt82_port_id' = '', `dhcp_opt82_port_id`, '\$dhcp_opt82_port_id'), `dhcp_opt82_vlan_id` = if('\$dhcp_opt82_vlan_id' = '', `dhcp_opt82_vlan_id`, '\$dhcp_opt82_vlan_id'), `dhcp_opt82_subscriber_id` = if('\$dhcp_opt82_subscriber_id' = '', `dhcp_opt82_subscriber_id`, '\$dhcp_opt82_subscriber_id');";

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
    $server->set('get_requested_data', $get_requested_data);
    $server->set('get_requested_data_opt82', $get_requested_data_opt82);
    $server->set('get_routing', $get_routing);
    $server->set('lease_offered', $lease_offered);
    $server->set('lease_nak', $lease_nak);
    $server->set('lease_decline', $lease_decline);
    $server->set('lease_release', $lease_release);
    $server->set('lease_success', $lease_success);
    $server->set('log_detailed', $log_detailed);
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
