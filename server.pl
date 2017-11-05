#!/usr/bin/env perl
use strict;
use warnings FATAL => 'all';
use Getopt::Long;
use Server;

my $server;
my ($BIND_ADDR, $SERVER_PORT, $CLIENT_PORT, $MIRROR, $DHCP_SERVER_ID, $THREADS_COUNT, $DBDATASOURCE, $DBLOGIN, $DBPASS, $PIDFILE, $DEBUG, $DAEMON);

my $get_requested_data_client = "SELECT * FROM `subnets`, `clients` WHERE `clients`.`mac` = '%s' AND `clients`.`subnet_id` = `subnets`.`subnet_id` AND `clients`.`ip` = '%s' LIMIT 1;";
my $get_requested_data_relay = "SELECT * FROM `subnets`, `clients` WHERE `clients`.`mac` = '%s' AND `clients`.`subnet_id` = `subnets`.`subnet_id` AND `subnets`.`gateway` = '%s' LIMIT 1;";
my $get_requested_data_guest = "SELECT * FROM `subnets`, `ips` WHERE `ips`.`mac` = '%s' AND `ips`.`subnet_id` = `subnets`.`subnet_id` AND `ips`.`ip` = '%s' LIMIT 1;";

my $get_requested_data_opt82 = "SELECT * FROM `subnets`, `ips` WHERE `subnets`.`vlan_id` = '%s' AND `subnets`.`subnet_id` = `ips`.`subnet_id` AND `subnets`.`type` = 'guest' AND (`ips`.`lease_time` IS NULL OR or `ips`.`lease_time` < UNIX_TIMESTAMP()) AND `ips`.`ip` NOT IN (SELECT `ip` FROM `clients`) LIMIT 1 ;";

my $get_routing = "SELECT `destination`, `mask` `gateway` FROM `subnets_routes` WHERE `subnet_id` = '%s' LIMIT 30;"; #done
my $lease_offered = "UPDATE `ips` SET `mac` = '%s', `lease_time` = UNIX_TIMESTAMP()+30 WHERE `ip` = '%s';"; #done
my $lease_nak = "UPDATE `ips` SET `lease_time` = NULL, `mac` = NULL WHERE `mac` = '%s' AND `ip` = '%s';"; #done
my $lease_decline = "INSERT INTO `dhcp_log` (`created`, `type`, `client_mac`,`client_ip`,`gateway_ip`,`client_ident`, `requested_ip`,`hostname`, `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`, `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`) VALUES (NOW(), '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');";
my $lease_release = "UPDATE `ips` SET `lease_time` = NULL, `mac` = NULL WHERE `mac` = '%s' AND `ip` = '%s';"; #done
my $lease_ack = "UPDATE `ips` SET `lease_time` = UNIX_TIMESTAMP()+3600, `mac` = '%s' WHERE `ip` = '%s';"; #done
my $log_detailed = "INSERT INTO `dhcp_log` (`created`,`type`,`client_mac`,`client_ip`,`gateway_ip`,`client_ident`,`requested_ip`,`hostname`, `dhcp_vendor_class`,`dhcp_user_class`,`dhcp_opt82_chasis_id`,`dhcp_opt82_unit_id`, `dhcp_opt82_port_id`, `dhcp_opt82_vlan_id`, `dhcp_opt82_subscriber_id`) VALUES (NOW(), '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');"; #done

&start();

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
    $server->set('get_requested_data_client', $get_requested_data_client);
    $server->set('get_requested_data_relay', $get_requested_data_relay);
    $server->set('get_requested_data_guest', $get_requested_data_guest);
    $server->set('get_requested_data_opt82', $get_requested_data_opt82);
    $server->set('get_routing', $get_routing);
    $server->set('lease_offered', $lease_offered);
    $server->set('lease_nak', $lease_nak);
    $server->set('lease_decline', $lease_decline);
    $server->set('lease_release', $lease_release);
    $server->set('lease_ack', $lease_ack);
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
