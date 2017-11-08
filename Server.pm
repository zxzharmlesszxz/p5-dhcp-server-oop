#!/bin/false
# Net::DHCPD::Server.pm
# Author: Denys Razumov

package Server; {

    use strict;
    use utf8;
    use warnings;
    use Thread;
    use Socket;
    use DBI;
    use Net::DHCP::Packet;
    use Net::DHCP::Constants;
    use Benchmark ':hireswallclock';
    use POSIX qw(setsid setuid strftime :signal_h);
    use Sys::Syslog;
    use Data::Dumper;

    binmode(STDOUT, ':utf8');

    BEGIN {
        require Sys::Syslog;
        Sys::Syslog->import('setlogsock', 'openlog', 'syslog', 'closelog');
        openlog("dhcp-perl", "ndelay,pid", "local0");
    }

    END {
        closelog();
    }

    sub new {
        my $class = shift;

        my $self = {
            name                     => 'Net::DHCPD::Server',
            version                  => '1.0',
            BIND_ADDR                => '0.0.0.0',
            SERVER_PORT              => '67',
            CLIENT_PORT              => '68',
            DHCP_SERVER_ID           => '',
            MIRROR                   => undef,
            DBDATASOURCE             => 'mysql:dhcp:127.0.0.1',
            DBLOGIN                  => 'dhcp',
            DBPASS                   => 'dhcp',
            THREADS_COUNT            => 4,
            PIDFILE                  => '/var/run/dhcpd.pid',
            DEBUG                    => 0,
            DAEMON                   => undef,
            fromaddr                 => undef,
            dhcpreq                  => undef,
            dhcpresp                 => undef,
            RUNNING                  => 0,
            lease_free               => '',
            lease_add                => '',
            lease_update             => '',
            lease_time_get           => '',
            lease_check              => '',
            lease_get                => '',
            lease_free_get           => '',
            is_fixed                 => '',
            lease_fixed_check        => '',
            lease_fixed_get          => '',
            get_routing              => '',

            get_requested_data       => '',
            get_requested_data_guest => '',
            get_requested_data_opt82 => '',
            log_detailed             => '',
            dbh                      => undef
        };

        bless $self, $class;

        return $self;
    } #done +-

    sub set {
        # my ($self) = shift;
        # my ($param) = $_[0];
        # my ($value) = $[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        if ($_[1] && $_[1] ne '') {
            $self->logger(1, "Set: $_[0] = '$_[1]'");
            $self->{$_[0]} = $_[1];
        }
    } #done

    sub signal_handler {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->set('RUNNING', 0);
        $self->stop();
        $_->kill('KILL')->detach() foreach Thread->list();
    } #done +-

    sub start {
        # my ($self) = shift;
        my ($self) = shift;

        if (!defined($self->{DHCP_SERVER_ID})) {
            $self->logger(0, "DHCP_SERVER_ID: must be real ip!");
            exit;
        }

        $self->logger(0, "BIND_ADDR: $self->{BIND_ADDR}, THREADS_COUNT: $self->{THREADS_COUNT}, PIDFILE: $self->{PIDFILE}");
        $self->daemon() if (defined($self->{DAEMON}));
        $self->{RUNNING} = 1;
        $self->run();
    } #done

    sub stop {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->{RUNNING} = 0;
        close($self->{SOCKET_RCV});
    } #done

    sub logger {
        # my ($self) = shift;
        # my ($level) = $_[0];
        # my ($message) = $_[1];
        my ($self) = shift;
        my ($tid) = Thread->tid();
        if ($self->{DEBUG} >= $_[0]) {
            syslog('info|local0', "Thread $tid: $_[1]");
            print STDOUT strftime "[%d/%b/%Y %H:%M:%S] ", localtime;
            print STDOUT "Thread $tid: $_[1]\n";
        }
    } #done

    sub daemon {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
        #POSIX::setuid(65534) or die "Can't set uid: $!\n"; # nobody
        POSIX::setsid or die "Can't start a new session: $!\n";
        defined(my $tm = POSIX::fork()) or die "Can't fork: $!\n";
        exit if $tm;
        POSIX::umask 0;
        POSIX::chdir("/");

        open(STDIN, "+>/dev/null") or die "Can't open STDIN: $!\n";
        open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!\n";
        open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!\n";

        $self->logger(0, "Daemon mode");
    } #done

    sub write_pid {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        if (defined($self->{PIDFILE})) {
            open FILE, "> $self->{PIDFILE}" || $self->logger(0, "PID file save error: $!");
            print FILE "$$\n";
            close FILE;
        }
    } #done

    sub add_mirror {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        if (defined($self->{MIRROR})) {
            $self->{ADDR_MIRROR} = sockaddr_in($self->{SERVER_PORT}, inet_aton($self->{MIRROR}));
        }
    } #done

    sub send_mirror {
        # my ($self) = shift;
        # my $dhcpresppkt = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        send($self->{SOCKET_RCV}, $_[0], 0, $self->{ADDR_MIRROR}) ||
            $self->logger(1, "send mirr error: $!") if (defined($self->{ADDR_MIRROR}));
    } #done

    sub open_socket {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        socket($self->{SOCKET_RCV}, PF_INET, SOCK_DGRAM, getprotobyname('udp')) || die "Socket creation error: $@\n";
        bind($self->{SOCKET_RCV}, sockaddr_in($self->{SERVER_PORT}, inet_aton($self->{BIND_ADDR}))) || die "bind: $!";
    } #done

    sub run {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        # write PID to file
        $self->write_pid();
        # broadcast address
        $self->{ADDR_BCAST} = sockaddr_in($self->{CLIENT_PORT}, INADDR_BROADCAST);
        $self->add_mirror();
        # open listening socket
        $self->open_socket();
        # start threads
        for (1 .. ($self->{THREADS_COUNT} - 1)) {Thread->new({ 'context' => 'void' }, sub {$self->request_loop()});}
        $self->request_loop();
        # delete PID file on exit
        if (defined($self->{PIDFILE})) {unlink($self->{PIDFILE});}
        $self->logger(0, "Main: END!");
    } #done +-

    sub request_loop {
        # my ($self) = shift;
        my ($self) = shift;
        my ($buf); # recv data

        my ($t0, $t1, $td); # perfomance data
        my $tid = Thread->tid(); # thread ID
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(0, "START");
        # each thread make its own connection to DB
        # connect($data_source, $username, $password, \%attr)
        # dbi:DriverName:database=database_name;host=hostname;port=port
        until ($self->{dbh} = DBI->connect("DBI:" . $self->{DBDATASOURCE}, $self->{DBLOGIN}, $self->{DBPASS})) {
            $self->logger(0, "Could not connect to database: $DBI::errstr");
            $self->logger(0, "Sleeping 10 sec to retry");
            sleep(10);
        }

        if (defined($self->{dbh}) == 0) {
            $self->logger(0, "Could not connect to database: $DBI::errstr");
            $self->thread_exit(1);
        }

        $self->{dbh}->{mysql_auto_reconnect} = 1;

        if ($tid != 0) {
            # disable signals receiving on creted threads and set handler for KILL signal
            my $sigset = POSIX::SigSet->new(SIGINT, SIGTERM, SIGHUP);    # define the signals to block
            my $old_sigset = POSIX::SigSet->new;        # where the old sigmask will be kept
            unless (defined sigprocmask(SIG_BLOCK, $sigset, $old_sigset)) {die "Could not unblock SIGINT\n";}

            $SIG{KILL} = sub {
                $self->logger(0, "END by sig handler");
                $self->{dbh}->disconnect;
                $self->thread_exit(0);
            };
        }

        while ($self->{RUNNING} == 1) {
            $buf = undef;

            eval {
                # catch fatal errors
                # receive packet
                $self->{fromaddr} = recv($self->{SOCKET_RCV}, $buf, 16384, 0) || $self->logger(0, "recv err: $!");

                next if ($!); # continue loop if an error occured

                # filter to small packets
                next if (length($buf) < 236); # 300

                if ($self->{DEBUG} > 0) {$t0 = Benchmark->new;}

                # parce data to dhcp structes
                $self->{dhcpreq} = Net::DHCP::Packet->new($buf);

                # filter bad params in head
                next if ($self->{dhcpreq}->op() != BOOTREQUEST || $self->{dhcpreq}->isDhcp() == 0);
                next if ($self->{dhcpreq}->htype() != HTYPE_ETHER || $self->{dhcpreq}->hlen() != 6);

                # bad DHCP message!
                next if ($self->get_req_param($self->{dhcpreq}, DHO_DHCP_MESSAGE_TYPE()) eq '');

                # Is message for us?
                next if ($self->check_for_me();

                # RRAS client, ignory them
                next if ($self->get_req_raw_param($self->{dhcpreq}, DHO_USER_CLASS()) eq "RRAS.Microsoft");

                # send duplicate of received packet to mirror
                $self->send_mirror($buf);
                # log all to db
                my ($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
                $self->{mac} = $self->FormatMAC(substr($self->{dhcpreq}->chaddr(), 0, (2 * $self->{dhcpreq}->hlen())));
                $self->GenDHCPRespPkt();
                $self->GetRelayAgentOptions($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
                $self->db_log_detailed();

                # handle packet
                my $type = $self->get_req_param($self->{dhcpreq}, DHO_DHCP_MESSAGE_TYPE());
                if ($type == DHCPDISCOVER) {$self->handle_discover();}#-> DHCPOFFER
                elsif ($type == DHCPREQUEST) {$self->handle_request();}#-> DHCPACK/DHCPNAK
                elsif ($type == DHCPDECLINE) {$self->handle_decline();}
                elsif ($type == DHCPRELEASE) {$self->handle_release();}
                elsif ($type == DHCPINFORM) {$self->handle_inform();}#-> DHCPACK
                else {}

                if ($self->{DEBUG} > 0) {
                    $t1 = Benchmark->new;
                    $td = timediff($t1, $t0);
                    $self->logger(2, "The code took: " . timestr($td));
                }
            }; # end of 'eval' blocks
            $self->logger(0, "Caught error in main loop: $@") if ($@);
        }

        $self->{dbh}->disconnect;

        $self->thread_exit(0);
    } #done +-

    sub thread_exit($) {
        # my ($self) = shift;
        # my ($code) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(0, "END code: " . $_[0]);

        # need to fix exit tread

        Thread->exit($_[0]) if Thread->can('exit');
        exit($_[0]);
    } #done +-

    sub send_reply {
        # my ($self) = shift;
        my ($self) = shift;
        my ($dhcpresppkt, $toaddr);
        # add last!!!!
        my $agent_opt = $self->get_req_raw_param($self->{dhcpreq}, DHO_DHCP_AGENT_OPTIONS());
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->{dhcpresp}->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $agent_opt) if ($agent_opt ne '');
        $dhcpresppkt = $self->{dhcpresp}->serialize();

        if ($self->{dhcpreq}->giaddr() eq '0.0.0.0') {
            # client local, not relayed
            # always broadcast DHCPNAK
            if ($self->{dhcpresp}->DHO_DHCP_MESSAGE_TYPE() == DHCPNAK) {$toaddr = $self->{ADDR_BCAST};}
            else {
                if ($self->{dhcpreq}->ciaddr() eq '0.0.0.0') {
                    # ALL HERE NON RFC 2131 4.1 COMPLIANT!!!
                    # perl can not send to hw addr unicast with ip 0.0.0.0, and we send broadcast
                    if ($self->{dhcpreq}->flags() == 0 || 1) {
                        # send unicast XXXXXXXXX - flags ignored!
                        # here we mast send unicast to hw addr, ip 0.0.0.0
                        my ($port, $addr) = unpack_sockaddr_in($self->{fromaddr});
                        my $ipaddr = inet_ntoa($addr);

                        if ($ipaddr eq '0.0.0.0') {$toaddr = $self->{ADDR_BCAST};}
                        # giaddr and ciaddr is zero but we know ip addr from received packet
                        else {$toaddr = sockaddr_in($self->{CLIENT_PORT}, $addr);}
                    }
                    # only this comliant to rfc 2131 4.1
                    else {$toaddr = $self->{ADDR_BCAST};}
                }
                # client have IP addr, send unicast
                else {$toaddr = sockaddr_in($self->{CLIENT_PORT}, $self->{dhcpreq}->ciaddrRaw());}
            }
        }
        # send to relay
        else {$toaddr = sockaddr_in($self->{SERVER_PORT}, $self->{dhcpreq}->giaddrRaw());}
        send($self->{SOCKET_RCV}, $dhcpresppkt, 0, $toaddr) || $self->logger(0, "send error: $!");

        my ($port, $addr) = unpack_sockaddr_in($toaddr);
        my $ipaddr = inet_ntoa($addr);
        $self->logger(1, "Sending response to = $ipaddr:$port length = " . length($dhcpresppkt));
        # send copy of packet to mirror, if specified
        $self->send_mirror($dhcpresppkt);
    } #done

    sub GenDHCPRespPkt {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);

        $self->{dhcpresp} = Net::DHCP::Packet->new(
            Op                           => BOOTREPLY(),
            Htype                        => $self->{dhcpreq}->htype(), #rfc2131 - From "Assigned Numbers" RFC
            Hlen                         => $self->{dhcpreq}->hlen(), #rfc2131 - must be 6 ipv4
            # Hops                       => $self->{dhcpreq->hops(),   #rfc2131 - must be 0
            Xid                          => $self->{dhcpreq}->xid(), #rfc2131 - must be from client DISCOVER
            Secs                         => $self->{dhcpreq}->secs(), #rfc2131 - must be 0
            Flags                        => $self->{dhcpreq}->flags(), #rfc2131 - must be from client DISCOVER
            #Ciaddr                      => $_[0]->ciaddr(), #rfc2131 - must be 0
            #Yiaddr                      => '0.0.0.0',       #rfc2131 - must be from IP for client DISCOVER(will be setted at the next step)
            Siaddr                       => $self->{dhcpreq}->siaddr(), #rfc2131 - must be from client DISCOVER if relayed
            Giaddr                       => $self->{dhcpreq}->giaddr(), #rfc2131 - must be from client DISCOVER
            Chaddr                       => $self->{dhcpreq}->chaddr(), #rfc2131 - must be from client DISCOVER
            DHO_DHCP_MESSAGE_TYPE()      => DHCPACK, # must be owerwritten
            DHO_DHCP_SERVER_IDENTIFIER() => $self->{DHCP_SERVER_ID}
        );
    } #done

    sub BuffToHEX($) {
        # my ($self) = shift;
        # my ($buf) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $_[0] =~ s/(.)/sprintf("%02x", ord($1))/eg;
        return ($_[0]);
    } #done

    sub unpackRelayAgent(%) {
        # my ($self) = shift;
        # my (@SubOptions) = @_;
        my ($self) = shift;
        my @SubOptions = @_;
        my $buf;
        $self->logger(9, "Function: " . (caller(0))[3]);

        for (my $i = 0; defined($SubOptions[$i]); $i += 2) {
            $buf .= "($SubOptions[$i])=" . $self->BuffToHEX($SubOptions[($i + 1)]) . ', ';
        }

        return ($buf);
    } #done

    sub GetRelayAgentOptions($$$$$$) {
        my ($self) = shift;
        # my $dhcp_opt82_vlan_id = $_[0];
        # my $dhcp_opt82_unit_id = $_[1];
        # my $dhcp_opt82_port_id = $_[2];
        # my $dhcp_opt82_chasis_id = $_[3];
        # my $dhcp_opt82_subscriber_id = $_[4];
        my @RelayAgent;
        $self->logger(9, "Function: " . (caller(0))[3]);
        # Set return values.
        $_[0] = $_[1] = $_[2] = $_[3] = $_[4] = '';
        # no options, return
        return(0) if (defined($self->{dhcpreq}->getOptionRaw(DHO_DHCP_AGENT_OPTIONS())) == 0);

        @RelayAgent = $self->{dhcpreq}->decodeRelayAgent($self->{dhcpreq}->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()));
        $self->logger(1, "RelayAgent: " . @RelayAgent);

        for (my $i = 0; defined($RelayAgent[$i]); $i += 2) {
            if ($RelayAgent[$i] == 1) {
                # Circuit ID
                $self->logger(1, "RelayAgent Circuit ID: " . $RelayAgent[($i + 1)]);
                next if (length($RelayAgent[($i + 1)]) < 4);
                # first bytes must be: 00 04
                # zte has 'eth 1/0/8:4096.444 0/0/0/0/0/0' (not packed string) /^(\w+)\s(\d+)\/(\d+)\/(\d+):(\d+)\.(\d+)\s(\d+)\/(\d+)\/(\d+)\/(\d+)\/(\d+)\/(\d+)$/
                #$_[0] = unpack('n', substr($RelayAgent[($i + 1)], -4, 2)); # may be 's'
                $RelayAgent[($i + 1)] =~ /(\d+)(?=\ )/;
                $_[0] = $1;
                $self->logger(1, "RelayAgent VLan: " . $_[0]);
                #$_[1] = unpack('C', substr($RelayAgent[($i + 1)], -2, 1));
                $RelayAgent[($i + 1)] =~ /(\d+)(?=\/\d+:)/;
                $_[1] = $1;
                $self->logger(1, "RelayAgent Unit: " . $_[1]);
                #$_[2] = unpack('C', substr($RelayAgent[($i + 1)], -1, 1));
                $RelayAgent[($i + 1)] =~ /(\d+)(?=:)/;
                $_[2] = $1;
                $self->logger(1, "RelayAgent Port: " . $_[2]);
            }
            elsif ($RelayAgent[$i] == 2) {
                # Remote ID
                next if (length($RelayAgent[($i + 1)]) < 6);
                # first bytes must be: 00 06 or 01 06 or 02 xx
                # first digit - format/data type, second - len
                $_[3] = $self->FormatMAC(unpack("H*", substr($RelayAgent[($i + 1)], - 6, 6)));
                $self->logger(1, "RelayAgent 4: " . $_[3]);
                # 02 xx - contain vlan num, undone
            }
            elsif ($RelayAgent[$i] == 6) {
                # Subscriber ID
                $_[4] = $RelayAgent[($i + 1)];
                $self->logger(1, "RelayAgent 5: " . $_[4]);
            }
            else {}
        }

        return (1);
    } #done +-(need to move this function to server.pl)

    sub FormatMAC {
        # my ($self) = shift;
        # my ($mac) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $_[0] =~ /([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})/i;
        return (lc(join(':', $1, $2, $3, $4, $5, $6)));
    } #done

    sub subnetBits {
        # my ($self) = shift;
        # my ($bits) = $_[0];
        my ($self) = shift;
        my $bcnt = 0;
        $self->logger(9, "Function: " . (caller(0))[3]);
        foreach (0 .. 31) {$bcnt++ if (vec(pack("L", unpack("N", pack("C4", split(/\./, $_[0])))), $_, 1) == 1);}
        return ($bcnt);
    } #done

    sub mk_classless_routes_bin_mask {
        # my ($self) = shift;
        # my $net = $_[0];
        # my $mask = $_[1];
        # my $gw = $_[2];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        return ($self->mk_classless_routes_bin_prefixlen($_[0], $self->subnetBits($_[1]), $_[2]));
    } #done

    sub mk_classless_routes_bin_prefixlen {
        # my ($self) = shift;
        # my $net = $_[0];
        # my $prefixlen = $_[1];
        # my $gw = $_[2];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        my ($str) = pack('C', $_[1]);

        if ($_[1] > 0) {
            my ($s1, $s2, $s3, $s4) = split(/\./, $_[0]);
            $str .= pack('C', $s1);
            $str .= pack('C', $s2) if ($_[1] > 8);
            $str .= pack('C', $s3) if ($_[1] > 16);
            $str .= pack('C', $s4) if ($_[1] > 24);
        }

        $str .= pack('CCCC', split(/\./, $_[2]));

        return ($str);
    } #done

    sub check_for_me {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        return ($self->get_req_raw_param($self->{dhcpreq}, DHO_DHCP_CLIENT_IDENTIFIER()) eq $self->{DHCP_SERVER_ID}) ? 1 : 0;
    } #done

    # handlers functions

    sub handle_discover {
        # my ($self) = shift;
        my $self = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->{dhcpresp}->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPOFFER);

        # ciaddr       = 0
        # chaddr       = client_mac
        # requested_ip = client_ip or 0.0.0.0
        # opt82        = true(always if enabled) or false

        $self->db_check_requested_data();
        if ($self->get_requested_data() == 1) {
            $self->lease_offered($self->{dhcpresp}->yiaddr(), 30);
        }
        else {
            # if AUTO_CONFIGURE (116) supported - send disable generate link local addr
            if ($self->get_req_param($self->{dhcpreq}, DHO_AUTO_CONFIGURE()) ne '') {
                $self->{dhcpresp}->addOptionValue(DHO_AUTO_CONFIGURE(), 0);
            }
        }
        $self->send_reply();
    }

    sub handle_request {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->db_check_requested_data();

        if ($self->get_requested_data() == 1) {
            if (($self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS()) ne $self->{dhcpresp}->yiaddr() && $self->{dhcpreq}->ciaddr() eq '0.0.0.0') ||
                ($self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS()) eq '' && $self->{dhcpreq}->ciaddr() ne $self->{dhcpresp}->yiaddr())) {
                # NAK if requested addr not equal IP addr in DB
                $self->logger(2, "Got REQUEST send NACK");
                $self->{dhcpresp}->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPNAK);
                $self->lease_nak($self->{dhcpreq}->ciaddr());
                $self->{dhcpresp}->ciaddr('0.0.0.0');
                $self->{dhcpresp}->yiaddr('0.0.0.0');
            }
            else {
                $self->logger(2, "Got REQUEST send ACK");
                $self->{dhcpresp}->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);
                $self->lease_ack($self->{dhcpresp}->yiaddr(), $self->get_req_param($self->{dhcpresp}, DHO_DHCP_LEASE_TIME()));
            }

            $self->send_reply();
        }
        else {
            $self->{dhcpresp}->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPNAK);
            $self->{dhcpresp}->ciaddr('0.0.0.0');
            $self->{dhcpresp}->yiaddr('0.0.0.0');
            $self->lease_nak($self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS()));
            $self->send_reply();
        }
    }

    sub handle_decline {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->db_check_requested_data();
        # ciaddr = 0
        # request_ip = client_ip
        $self->db_lease_decline();
    } #done

    sub handle_release {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->db_check_requested_data();
        $self->lease_release();
    } #done - done

    sub handle_inform {
        # my ($self) = shift;
        my ($self) = shift;
        my ($dhcpreqparams);
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, "Got REQUEST send ACK");
        $self->db_check_requested_data();
        $self->{dhcpresp}->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);

        # ciaddr = client_ip
        # request_ip = 0
        if ($self->get_requested_data() == 1) {
            $dhcpreqparams = $self->get_req_param($self->{dhcpreq}, DHO_DHCP_PARAMETER_REQUEST_LIST());
            $self->static_data_to_reply($dhcpreqparams);
        }

        $self->send_reply();
    }


    # Need to delete fromaddr from db-functions
    sub db_check_requested_data {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        my $requested_ip = $self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS());
        my $yiaddr = $self->{dhcpreq}->yiaddr();
        my $ciaddr = $self->{dhcpreq}->ciaddr();
        my $giaddr = $self->{dhcpreq}->giaddr();
        $self->logger(2, $self->{dhcpreq}->toString());
        $self->logger(3, "mac = $self->{mac} requested_ip = $requested_ip yiaddr = $yiaddr ciaddr = $ciaddr giaddr = $giaddr");
        return;
    }

    sub static_data_to_reply {
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        #my $dhcpreqparams = $_[0];
        # do not add params if not requested
        return() if (defined($_[0]) == 0);
        if (index($_[0], DHO_ROUTER_DISCOVERY()) != - 1) {$self->{dhcpresp}->addOptionValue(DHO_ROUTER_DISCOVERY(), 0);}
        if (index($_[0], DHO_NTP_SERVERS()) != - 1) {$self->{dhcpresp}->addOptionValue(DHO_NTP_SERVERS(), '8.8.8.8 8.8.8.8');}
        if (index($_[0], DHO_NETBIOS_NODE_TYPE()) != - 1) {$self->{dhcpresp}->addOptionValue(DHO_NETBIOS_NODE_TYPE(), 8);} # H-Node
        # Option 43 must be last for Windows XP proper work
        # https://support.microsoft.com/en-us/kb/953761
        if (index($_[0], DHO_VENDOR_ENCAPSULATED_OPTIONS()) != - 1) {
            # 001 - NetBIOS over TCP/IP (NetBT): 00000002 (2) - disabled
            # 002 - Release DHCP Lease on Shutdown: 00000001 (1) - enabled
            # 255 - END
            $self->{dhcpresp}->addOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS(),
                "\x01\x04\x00\x00\x00\x02\x02\x04\x00\x00\x00\x01\xff");
        }
    }

    sub get_requested_data {
        # my ($self) = shift;
        my ($self) = shift;
        my ($result);
        my $lease = 0;
        my ($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        my $dhcpreqparams = $self->get_req_param($self->{dhcpreq}, DHO_DHCP_PARAMETER_REQUEST_LIST());
        my $requested_ip = ($self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS()) ne '') ? $self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS()) : '0.0.0.0' ;
        my $ip = $self->{dhcpreq}->ciaddr();
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(9, sprintf("ip = %s, requested_ip = %s", $ip, $requested_ip));

        # bound/renew/rebind
        # ciaddr = client_ip
        # request_ip = ''
        if ($ip ne '0.0.0.0') {
            my $fixed_lease = $self->get_fixed_lease($ip, $self->{mac});
            $lease = $fixed_lease ? $fixed_lease : $self->get_lease($ip, $self->{mac});
        }
        # request
        # ciaddr = 0.0.0.0
        # request_ip = client_ip
        elsif ($requested_ip ne '0.0.0.0') {
            my $fixed_lease = $self->get_fixed_lease($requested_ip, $self->{mac});
            $lease = $fixed_lease ? $fixed_lease : $self->get_lease($requested_ip, $self->{mac});
        }

        # lease exists
        if ($lease != 0) {
            $self->logger(0, sprintf("LEASE: Exists %s %s %s", $lease->{ip}, $lease->{mac}, $lease->{lease_time}));
            $self->GetRelayAgentOptions($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
            $self->db_get_requested_data($result, $lease->{subnet_id}, '');
            if ($result != 0) {
                $self->{dhcpresp}->yiaddr($lease->{ip});
                $self->db_data_to_reply($result, $dhcpreqparams);
                $self->db_get_routing($dhcpreqparams, $lease->{subnet_id});
                $self->static_data_to_reply($dhcpreqparams);
                return (1);
            }
        }
        # lease doesn't exists
        else {
            $self->logger(0, sprintf("LEASE: Doesn't exists for %s %s", $self->{mac}, (($ip ne '0.0.0.0') ? $ip : $requested_ip)));
            $self->logger(3, sprintf("LEASE: Try to get free lease for %s %s", $self->{mac}, (($ip ne '0.0.0.0') ? $ip : $requested_ip)));
            $self->GetRelayAgentOptions($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
            # need subnet_id
            $self->get_subnet_id(my $subnet, $self->{dhcpreq}->giaddr());
            $self->logger(3, sprintf("SUBNET: %s", $subnet->{subnet_id}));
            if ($self->is_fixed($subnet->{subnet_id})) {
                $self->db_get_requested_data($result, $subnet->{subnet_id});
                $self->get_free_lease($lease, $subnet->{subnet_id});
                if ($lease == 0 && $lease->{ip}) {
                    $self->{dhcpresp}->yiaddr($lease->{ip});
                    $self->db_data_to_reply($result, $dhcpreqparams);
                    $self->db_get_routing($dhcpreqparams, $result->{subnet_id});
                    $self->static_data_to_reply($dhcpreqparams);
                    return (1);
                }
            }
            else {
                $self->get_subnet_id($subnet, $self->{dhcpreq}->giaddr(), 'guest');
                $self->logger(3, sprintf("SUBNET: %s", $subnet->{subnet_id}));
                $self->db_get_requested_data($result, $subnet->{subnet_id});
                $self->get_free_lease($lease, $subnet->{subnet_id});
                if ($lease == 0 && $lease->{ip}) {
                    $self->{dhcpresp}->yiaddr($lease->{ip});
                    $self->db_data_to_reply($result, $dhcpreqparams);
                    $self->db_get_routing($dhcpreqparams, $result->{subnet_id});
                    $self->static_data_to_reply($dhcpreqparams);
                    return (1);
                }
            }
        }

        return (0);
    }

    sub db_get_requested_data {
        # my ($self) = shift;
        # my $result = $_[0];
        # my ($subnet_id) = $_[1];
        my ($self) = shift;
        my $sth;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("SQL: subnet_id = %s", $_[1]));

        if ($_[1]) {
            $sth = $self->{dbh}->prepare(sprintf("SELECT * FROM `subnets` WHERE `subnet_id` = '%s' LIMIT 1;", $_[1]));
            $sth->execute();
            if ($sth->rows()) {
                $_[0] = $sth->fetchrow_hashref();
                $sth->finish();
                return (1);
            }
            $sth->finish();
        }
        else {
            return(0);
        }
        return (0);
    }

    sub get_subnet_id {
        # my ($self) = shift;
        # my $result = $_[0];
        # my ($gw) = $_[1];
        # my ($type) = $_[2];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("SUBNET: get subnet_id by gw = %s", $_[1])) if (defined($_[2]) == 0);
        $self->logger(2, sprintf("SUBNET: get subnet_id by gw = %s and type = %s", $_[1], $_[2])) if (defined($_[2]));
        $self->db_get_subnet_id($_[0], $_[1], $_[2]);
    }

    sub db_get_subnet_id {
        # my ($self) = shift;
        # my $result = $_[0];
        # my ($gw) = $_[1];
        # my ($type) = $_[2];
        my ($self) = shift;
        my $sth;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("SQL: get subnet_id by gw = %s", $_[1])) if (defined($_[2]) == 0);
        $self->logger(2, sprintf("SQL: get subnet_id by gw = %s and type = %s", $_[1], $_[2])) if (defined($_[2]));

        if ($_[2]) {
            $sth = $self->{dbh}->prepare(sprintf("SELECT `subnet_id` FROM `subnets` WHERE `gateway` = '%s' AND `type` = '%s' LIMIT 1;", $_[1], $_[2]));
        }
        else {
            $sth = $self->{dbh}->prepare(sprintf("SELECT `subnet_id` FROM `subnets` WHERE `gateway` = '%s' AND `type` != 'guest' LIMIT 1;", $_[1]));
        }

        $sth->execute();
        if ($sth->rows()) {
            $_[0] = $sth->fetchrow_hashref();
            $sth->finish();
            return (1);
        }

        $sth->finish();
        return (0);

    }

    sub db_data_to_reply {
        # my ($self) = shift;
        # my $result = $_[0];
        # my $dhcpreqparams = $_[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        if (defined($_[0]->{dhcp_lease_time})) {
            $self->{dhcpresp}->addOptionValue(DHO_DHCP_LEASE_TIME(), $_[0]->{dhcp_lease_time});

            # function (typically 50%) of the full configured duration (or lease time) for a client's lease
            if (defined($_[0]->{dhcp_renewal})) {
                $self->{dhcpresp}->addOptionValue(DHO_DHCP_RENEWAL_TIME(), $_[0]->{dhcp_renewal});
                #} else {
                #	$self->{dhcpresp}->addOptionValue(DHO_DHCP_RENEWAL_TIME(), ($_[0]->{dhcp_lease_time}/2));
            }

            # function (typically 87.5%) of the full configured duration (or lease time) for a client's lease
            if (defined($_[0]->{dhcp_rebind_time})) {
                $self->{dhcpresp}->addOptionValue(DHO_DHCP_REBINDING_TIME(), $_[0]->{dhcp_rebind_time});
                #} else {
                #	$self->{dhcpresp}->addOptionValue(DHO_DHCP_REBINDING_TIME(), ($_[0]->{dhcp_lease_time}*7/8));
            }
        }

        # do not add params if not requested
        return() if (defined($_[1]) == 0);

        if (index($_[1], DHO_SUBNET_MASK()) != - 1 && defined($_[0]->{mask})) {$self->{dhcpresp}->addOptionValue(DHO_SUBNET_MASK(),
            $_[0]->{mask});}
        if (index($_[1], DHO_ROUTERS()) != - 1 && defined($_[0]->{gateway})) {$self->{dhcpresp}->addOptionValue(DHO_ROUTERS(),
            $_[0]->{gateway});}
        if (index($_[1], DHO_DOMAIN_NAME_SERVERS()) != - 1 && defined($_[0]->{dns1})) {$self->{dhcpresp}->addOptionValue(
            DHO_DOMAIN_NAME_SERVERS(), "$_[0]->{dns1} $_[0]->{dns2}");}
        if (index($_[1], DHO_HOST_NAME()) != - 1 && defined($_[0]->{hostname})) {$self->{dhcpresp}->addOptionValue(DHO_HOST_NAME(),
            $_[0]->{hostname});}
        if (index($_[1], DHO_DOMAIN_NAME()) != - 1 && defined($_[0]->{domain})) {$self->{dhcpresp}->addOptionValue(
            DHO_DOMAIN_NAME(), $_[0]->{domain});}
    }

    sub db_get_routing {
        # my ($self) = shift;
        # my $dhcpreqparams = $_[0];
        # my $subnet_id = $_[1];
        my ($self) = shift;
        my ($sth, $opt33Enbled, $optClasslessRoutesCode);
        $self->logger(9, "Function: " . (caller(0))[3]);
        # do not add routes if not requested
        return() if (defined($_[0]) == 0);
        $opt33Enbled = index($_[0], DHO_STATIC_ROUTES());
        $opt33Enbled = undef if ($opt33Enbled == - 1);
        $optClasslessRoutesCode = index($_[0], 121);

        if ($optClasslessRoutesCode == - 1) {
            $optClasslessRoutesCode = index($_[0], 249); # MSFT
            if ($optClasslessRoutesCode == - 1) {$optClasslessRoutesCode = undef;}
            else {
                $opt33Enbled = undef;
                $optClasslessRoutesCode = 249;
            }
        }
        else {
            $opt33Enbled = undef;
            $optClasslessRoutesCode = 121;
        }

        return () if (defined($opt33Enbled) == 0 && defined($optClasslessRoutesCode) == 0);

        $self->logger(2, sprintf("SQL: $self->{get_routing}", $_[1]));
        $sth = $self->{dbh}->prepare(sprintf($self->{get_routing}, $_[1]));
        $sth->execute();
        if ($sth->rows()) {
            my ($ref, $row);
            my $opt33_data = undef; # routes to single hosts
            my $opt_classless_routes_data = undef; # routes to nets

            $ref = $sth->fetchall_arrayref;
            foreach $row (@{$ref}) {
                if (defined($opt33Enbled) && @$row[1] eq '255.255.255.255') {
                    # pack dst
                    $opt33_data .= pack('CCCC', split(/\./, @$row[0]));

                    # pack gw
                    $opt33_data .= pack('CCCC', split(/\./, @$row[2]));
                }
                $opt_classless_routes_data .= $self->mk_classless_routes_bin_mask(@$row[0], @$row[1],
                    @$row[2]) if (defined($optClasslessRoutesCode));
            }

            $self->{dhcpresp}->addOptionRaw(DHO_STATIC_ROUTES(), $opt33_data) if (defined($opt33_data));
            $self->{dhcpresp}->addOptionRaw($optClasslessRoutesCode,
                $opt_classless_routes_data) if (defined($opt_classless_routes_data));
        }
        $sth->finish();
    }

    sub lease_offered {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        # my ($lease_time) = $_[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(0, sprintf("LEASE: Success OFFERED IP=%s for MAC=%s", $_[0], $self->{mac})) if ($self->add_lease($_[0], $_[1]) == 1);
    } #done - done

    sub lease_nak {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->free_lease($_[0]);
    } #done - done

    sub db_lease_decline {
        # my ($self) = shift;
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);

        # this function need to understand how to must work
        #
        # request_ip = client_ip
        # ciaddr = 0

        $self->logger(0, sprintf("Need to add functionality to this function, IP = %s already obtained by other client", $self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS())));
        #my $sth = $self->{dbh}->prepare("");
        #$sth->execute();
        #$sth->finish();

        return (0);
    } #done

    sub lease_release {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->free_lease($self->{dhcpreq}->ciaddr());
    } #done

    sub lease_ack {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        # my ($lease_time) = $_[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->update_lease_time($_[0], $_[1]);
    } #done - done

    sub db_log_detailed {
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        my ($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        my $client_ip = $self->{dhcpreq}->ciaddr();
        my $gateway_ip = $self->{dhcpreq}->giaddr();
        my $client_ident = $self->BuffToHEX($self->get_req_raw_param($self->{dhcpreq}, DHO_DHCP_CLIENT_IDENTIFIER()));
        my $requested_ip = $self->get_req_param($self->{dhcpreq}, DHO_DHCP_REQUESTED_ADDRESS());
        my $hostname = $self->get_req_param($self->{dhcpreq}, DHO_HOST_NAME());
        my $dhcp_vendor_class = $self->get_req_param($self->{dhcpreq}, DHO_VENDOR_CLASS_IDENTIFIER());
        my $dhcp_user_class = $self->get_req_param($self->{dhcpreq}, DHO_USER_CLASS());
        my $type = $self->get_req_param($self->{dhcpreq}, DHO_DHCP_MESSAGE_TYPE());
        $self->GetRelayAgentOptions($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id,
            $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        $self->logger(3, sprintf("SQL: $self->{log_detailed}", $type, $self->{mac}, $client_ip, $gateway_ip,
            $client_ident, $requested_ip, $hostname, $dhcp_vendor_class, $dhcp_user_class, $dhcp_opt82_chasis_id,
            $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_vlan_id, $dhcp_opt82_subscriber_id));
        my $sth = $self->{dbh}->prepare(sprintf($self->{log_detailed}, $type, $self->{mac}, $client_ip, $gateway_ip,
            $client_ident, $requested_ip, $hostname, $dhcp_vendor_class, $dhcp_user_class, $dhcp_opt82_chasis_id,
            $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_vlan_id, $dhcp_opt82_subscriber_id));
        $sth->execute();
        $sth->finish();
    } #done

    # params functions
    # return value of param
    sub get_req_param {
        # my ($self) = shift;
        # my $dhcppacket = $_[0];
        # my $param = $_[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        return defined($_[0]->getOptionRaw($_[1])) ? $_[0]->getOptionValue($_[1]) : '';
    } #done

    # return raw value of param
    sub get_req_raw_param {
        # my ($self) = shift;
        # my $dhcppacket = $_[0];
        # my $param = $_[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        return defined($_[0]->getOptionRaw($_[1])) ? $_[0]->getOptionRaw($_[1]) : '';
    } #done

    # lease functions

    # add lease (return -1,0,1)
    sub add_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($result) = 0;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(3, sprintf("LEASE: Try to add lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $result = $self->db_add_lease($_[0]) if ($self->check_lease($_[0]) == 0);
        if ($result == 1) {
            $self->logger(0, sprintf("LEASE: Added lease time %s for IP = %s and MAC = %s", $self->get_lease_time($_[0]), $_[0], $self->{mac}));
        }
        else {
            $self->logger(0, sprintf("LEASE: Not added lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        return ($result);
    } #done - done

    sub db_add_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        $self->logger(3, sprintf("SQL: Try to add lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_add}", $self->{mac}, $_[0]));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_add}, $self->{mac}, $_[0]));
        my $result = $sth->execute();
        $sth->finish();
        return ($result);
    } #done - done

    # fixed leases
    sub is_fixed {
        # my ($self) = shift;
        # my ($subnet_id) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Check is static lease for MAC = %s in SUBNET = %s", $self->{mac}, $_[0]));
        return $self->db_is_fixed_lease($_[0]);
    }

    sub db_is_fixed_lease {
        # my ($self) = shift;
        # my ($subnet_id) = $_[0];
        my ($self) = shift;
        my ($lease) = 0;
        $self->logger(3, sprintf("SQL: Check is fixed lease for MAC = %s in SUBNET = %s", $self->{mac}, $_[0]));
        $self->logger(3, sprintf("SQL: $self->{is_fixed}", $self->{mac}, $_[0]));
        my $sth = $self->{dbh}->prepare(sprintf($self->{is_fixed}, $self->{mac}, $_[0]));
        $sth->execute();
        $lease = $sth->rows();
        $sth->finish();
        return $lease;
    } #done - done

    # get fixed lease (return array|undef)
    sub get_fixed_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to get static lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        return $self->db_get_fixed_lease($_[0]) if ($self->check_fixed_lease($_[0]));
    }

    sub db_get_fixed_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($lease) = undef;
        $self->logger(3, sprintf("SQL: Try to get fixed lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_fixed_get}", $_[0], $self->{mac}, $self->{mac}));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_fixed_get}, $_[0], $self->{mac}, $self->{mac}));
        $sth->execute();
        $lease = $sth->fetchrow_hashref() if ($sth->rows());
        $sth->finish();
        return $lease;
    } #done - done

    #check fixed lease if exists (return 0,1)
    sub check_fixed_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($result) = 0;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to find fixed lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->db_check_fixed_lease($_[0], $result);
        if ($result == 1) {
            $self->logger(0, sprintf("LEASE: Found fixed for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        else {
            $self->logger(0, sprintf("LEASE: Not found fixed for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        return ($result);
    } #done - done

    sub db_check_fixed_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        # my ($result) = $_[1];
        my ($self) = shift;
        $self->logger(3, sprintf("SQL: Try to find fixed lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_fixed_check}", $_[0], $self->{mac}, $self->{mac}));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_fixed_check}, $_[0], $self->{mac}, $self->{mac}));
        $sth->execute();
        $_[1] = $sth->rows();
        $sth->finish();
    } #done - done

    # get lease (return array|undef)
    sub get_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to get lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        return $self->db_get_lease($_[0]) if ($self->check_lease($_[0]));
    } #done - done

    sub db_get_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($lease) = undef;
        $self->logger(3, sprintf("SQL: Try to get lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_get}", $_[0], $self->{mac}));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_get}, $_[0], $self->{mac}));
        $sth->execute();
        $lease = $sth->fetchrow_hashref() if ($sth->rows());
        $sth->finish();
        return $lease;
    } #done - done

    # get free lease (return array|undef)
    sub get_free_lease {
        # my ($self) = shift;
        # my ($lease) = $_[0];
        # my ($subnet_id) = $_[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to get free lease for subnet_id = %s", $_[1]));
        $self->db_get_free_lease($_[0], $_[1]);
    } #done - done

    sub db_get_free_lease {
        # my ($self) = shift;
        # my ($lease) = $_[0];
        # my ($subnet_id) = $_[1];
        my ($self) = shift;
        $self->logger(3, sprintf("SQL: Try to get free lease for subnet_id = %s", $_[1]));
        $self->logger(3, sprintf("SQL: $self->{lease_free_get}", $_[1]));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_free_get}, $_[1]));
        $sth->execute();
        $_[0] = $sth->fetchrow_hashref() if ($sth->rows());
        $sth->finish();
    } #done - done

    #check lease if exists (return 0,1)
    sub check_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($result) = 0;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to find lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->db_check_lease($_[0], $result);
        if ($result == 1) {
            $self->logger(0, sprintf("LEASE: Found for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        else {
            $self->logger(0, sprintf("LEASE: Not found for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        return ($result);
    } #done - done

    sub db_check_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        # my ($result) = $_[1];
        my ($self) = shift;
        $self->logger(3, sprintf("SQL: Try to find lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_check}", $_[0], $self->{mac}));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_check}, $_[0], $self->{mac}));
        $sth->execute();
        $_[1] = $sth->rows();
        $sth->finish();
    } #done - done

    # free lease (return -1,0,1)
    sub free_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($result) = 0;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to free lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->db_free_lease($_[0], $result) if ($self->check_lease($_[0]));
        $self->logger(0, sprintf("LEASE: %s", $result));
        if ($result == 1) {
            $self->logger(0, sprintf("LEASE: Removed for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        else {
            $self->logger(0, sprintf("LEASE: Not removed for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        return ($result);
    } #done - done

    sub db_free_lease {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        # my ($result) = $_[1];
        my ($self) = shift;
        $self->logger(3, sprintf("SQL: Try to free lease for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_free}", $_[0], $self->{mac}));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_free}, $_[0], $self->{mac}));
        $sth->execute();
        $_[1] = $sth->rows();
        $sth->finish();
    } #done - done

    # get lease time (return lease time in seconds)
    sub get_lease_time {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($time) = undef;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to get lease time for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $time = $self->db_get_lease_time($_[0]) if ($self->check_lease($_[0]));
        if (defined($time) != 0) {
            $self->logger(0, sprintf("LEASE: Lease time for IP = %s and MAC = %s is %s ", $_[0], $self->{mac}, $time));
        }
        else {
            $self->logger(0, sprintf("LEASE: Cann't get lease time for IP = %s and MAC = %s", $_[0], $self->{mac}));
        }
        return ($time);
    } #done - done

    sub db_get_lease_time {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        my ($self) = shift;
        my ($result) = 0;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(3, sprintf("SQL: Try to get lease time for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_time_get}", $_[0], $self->{mac}));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_time_get}, $_[0], $self->{mac}));
        $sth->execute();
        $result = $sth->fetchrow_hashref() if ($sth->rows());
        $sth->finish();
        return $result->{lease_time};
    } #done - done

    # update lease time (return -1,0,1)
    sub update_lease_time {
        # my ($self) = shift;
        # my ($ip) = $_[0];
        # my ($lease_time) = $_[1];
        my ($self) = shift;
        my ($result) = 0;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(2, sprintf("LEASE: Try to update lease time for IP = %s and MAC = %s", $_[0], $self->{mac}));
        $result = $self->db_update_lease_time($_[1], $_[0]) if ($self->check_lease($_[0]));
        if ($result == 1) {
            $self->logger(0, sprintf("LEASE: Updated lease time %s for IP = %s and MAC = %s", $self->get_lease_time($_[0]), $_[0], $self->{mac}));
        }
        else {
            $self->logger(0, sprintf("LEASE: Not updated lease time %s for IP = %s and MAC = %s", $self->get_lease_time($_[0]), $_[0], $self->{mac}));
        }
        return ($result);
    } #done - done

    sub db_update_lease_time {
        # my ($self) = shift;
        # my ($lease_time) = $_[0];
        # my ($ip) = $_[1];
        my ($self) = shift;
        $self->logger(9, "Function: " . (caller(0))[3]);
        $self->logger(3, sprintf("SQL: Try to update lease time for IP = %s and MAC = %s", $_[1], $self->{mac}));
        $self->logger(3, sprintf("SQL: $self->{lease_update}", $_[0], $_[1], $self->{mac}));
        my $sth = $self->{dbh}->prepare(sprintf($self->{lease_update}, $_[0], $_[1], $self->{mac}));
        my $result = $sth->execute();
        $sth->finish();
        return ($result);
    } #done - done
}

1;
