#!/usr/bin/env perl
use strict;
use warnings FATAL => 'all';
use Getopt::Long;
use Server;

my ($BIND_ADDR, $SERVER_PORT, $CLIENT_PORT, $MIRROR, $DHCP_SERVER_ID);
my ($THREADS_COUNT, $PIDFILE, $DEBUG, $DAEMON);
my ($DBDATASOURCE, $DBLOGIN, $DBPASS);

my $get_requested_data_opt82 = "SELECT * FROM `subnets`, `ips` WHERE `subnets`.`vlan_id` = '%s' AND `subnets`.`subnet_id` = `ips`.`subnet_id` AND `subnets`.`type` = 'guest' AND (`ips`.`lease_time` IS NULL OR or `ips`.`lease_time` < UNIX_TIMESTAMP()) AND `ips`.`ip` NOT IN (SELECT `ip` FROM `clients`) LIMIT 1 ;";

my $get_subnet           = "SELECT * FROM `subnets` WHERE `subnet_id` = %s LIMIT 1;"; #done
my $get_subnet_guest     = "SELECT `subnet_id` FROM `subnets` WHERE `gateway` = '%s' AND `type` = '%s' LIMIT 1;"; #done
my $get_subnet_gw        = "SELECT `subnet_id` FROM `subnets` WHERE `gateway` = '%s' AND `type` != 'guest' LIMIT 1;"; #done
my $get_routing          = "SELECT `destination`, `mask` `gateway` FROM `subnets_routes` WHERE `subnet_id` = '%s' LIMIT 30;"; #done - done
my $lease_free           = "UPDATE `ips` SET `lease_time` = NULL, `mac` = NULL WHERE `ip` = '%s' AND `mac` = '%s';"; #done - done
my $lease_add            = "UPDATE `ips` SET `lease_time` = UNIX_TIMESTAMP()+30, `mac` = '%s' WHERE `ip` = '%s';"; #done - done
my $lease_update         = "UPDATE `ips` SET `lease_time` = UNIX_TIMESTAMP()+%d WHERE `ip` = '%s' AND `mac` = '%s';"; #done - done
my $lease_time_get       = "SELECT `lease_time` FROM `ips` WHERE `ip` = '%s' AND `mac` = '%s' LIMIT 1;"; #done - done
my $lease_check          = "SELECT * FROM `subnets`, `ips` WHERE `ips`.`ip` = '%s' AND `ips`.`mac` = '%s' AND `ips`.`subnet_id` = `subnets`.`subnet_id` LIMIT 1;"; #done - done
my $lease_get            = "SELECT * FROM `ips` WHERE `ip` = '%s' AND `mac` = '%s' LIMIT 1;"; #done - done
my $lease_fixed_check    = "SELECT * FROM `subnets`, `ips` WHERE `ips`.`ip` = '%s' AND `ips`.`mac` = '%s' AND `ips`.`subnet_id` = `subnets`.`subnet_id` AND `ips`.`ip` IN (SELECT `ip` FROM `clients` WHERE `mac` = '%s') LIMIT 1;"; #done - done
my $lease_fixed_get      = "SELECT * FROM `ips` WHERE `ip` = '%s' AND `mac` = '%s' AND `ip` IN (SELECT `ip` FROM `clients` WHERE `mac` = '%s') LIMIT 1;"; #done - done
my $lease_fixed_get2     = "SELECT * FROM `ips` WHERE `subnet_id` = '%s' AND `ip` IN (SELECT `ip` FROM `clients` WHERE `mac` = '%s') LIMIT 1;"; #done - done
my $lease_free_get       = "SELECT * FROM `ips` WHERE `subnet_id` = '%s' AND `mac` IS NULL AND `ip` NOT IN (SELECT `ip` FROM `clients`) LIMIT 1;";
my $is_fixed             = "SELECT * FROM `clients` WHERE `mac` = '%s' AND `subnet_id` = '%s' LIMIT 1;"; #done - done
my $log_detailed         = "INSERT INTO `dhcp_log` (`created`,`type`,`client_mac`,`client_ip`,`gateway_ip`,`client_ident`,`requested_ip`,`hostname`, `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`, `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`) VALUES (NOW(), '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %s, %s, %s, %s, %s);"; #done

if ($#ARGV == - 1) {usage();}

my $server = Server->new();
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
$server->set('lease_free', $lease_free);
$server->set('lease_add', $lease_add);
$server->set('lease_update', $lease_update);
$server->set('lease_time_get', $lease_time_get);
$server->set('lease_check', $lease_check);
$server->set('lease_get', $lease_get);
$server->set('lease_free_get', $lease_free_get);
$server->set('is_fixed', $is_fixed);
$server->set('lease_fixed_check', $lease_fixed_check);
$server->set('lease_fixed_get', $lease_fixed_get);
$server->set('lease_fixed_get2', $lease_fixed_get2);
$server->set('get_routing', $get_routing);

$server->set('get_subnet', $get_subnet);
$server->set('get_subnet_gw', $get_subnet_gw);
$server->set('get_subnet_guest', $get_subnet_guest);
$server->set('get_requested_data_opt82', $get_requested_data_opt82);
$server->set('log_detailed', $log_detailed);
$server->start();

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
