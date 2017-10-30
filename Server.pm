#!/bin/false
# Net::DHCPD::Server.pm
# Author: Denys Razumov

package Server; {

    use strict;
    use utf8;
    use warnings;
    use threads;
    use threads::shared;
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
        Sys::Syslog->import( 'setlogsock', 'openlog', 'syslog', 'closelog' );
        openlog("dhcp-perl", "ndelay,pid", "local0");
    }

    END {
        closelog();
    }

    sub new {
        my $class = shift;

        my $self = {
            name => 'Net::DHCPD::Server',
            version => '1.0',
            BIND_ADDR => '0.0.0.0',
            SERVER_PORT => '67',
            CLIENT_PORT => '68',
            DHCP_SERVER_ID => '',
            MIRROR => undef,
            DBDATASOURCE => 'mysql:dhcp:127.0.0.1',
            DBLOGIN => 'dhcp',
            DBPASS => 'dhcp',
            THREADS_COUNT => 4,
            PIDFILE => '/var/run/dhcpd.pid',
            DEBUG => 0,
            DAEMON => undef,
            RUNNING => 0,
            get_requested_data => '',
            get_requested_data_opt82 => '',
            get_routing => '',
            lease_offered => '',
            lease_nak => '',
            lease_decline => '',
            lease_release => '',
            lease_success => '',
            log_detailed => ''
        };

        bless $self, $class;
    
        return $self;
    }

    sub set {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        my ($param, $value);
        $param = shift;
        $value = shift;
        if ($value && $value ne '' ) {
            $self->logger("Set: $param = '$value' " . (caller(0))[3]) if ($self->{DEBUG} > 1);
            $self->{$param} = $value;
        }
    }

    sub signal_handler {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        $self->set('RUNNING', 0);
        $self->stop();
        $_->kill('KILL')->detach() foreach threads->list();
    }
    
    sub start {
        my($self) = shift;

        if (!defined($self->{DHCP_SERVER_ID})) {
            $self->logger("DHCP_SERVER_ID: must be real ip!");
            exit;
        }

        $self->logger("BIND_ADDR: $self->{BIND_ADDR}, THREADS_COUNT: $self->{THREADS_COUNT}, PIDFILE: $self->{PIDFILE}");

        if (defined($self->{DAEMON})) {
            $self->set('DEBUG', 0);
            $self->daemon();
        }
        
        $self->{RUNNING} = 1;
        $self->run();
    }

    sub stop {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        $self->{RUNNING} = 0;
        close($self->{SOCKET_RCV});
    }

    sub logger {
        my($self) = shift;
        syslog('info|local0', $_[0]);
        if ($self->{DEBUG} == 0) {return;}
    
        print STDOUT strftime "[%d/%b/%Y %H:%M:%S] ", localtime;
        print STDOUT $_[0] . "\n";
    }
    
    sub daemon {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
        #setuid(65534)		or die "Can't set uid: $!\n"; # nobody

        open(STDIN, "+>/dev/null") or die "Can't open STDIN: $!\n";
        open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!\n";
        open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!\n";
        defined(my $tm = fork) or die "Can't fork: $!\n";
        exit if $tm;
        setsid or die "Can't start a new session: $!\n";
        umask 0;

        $self->logger("Daemon mode");
    }
    
    sub run {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        # write PID to file
        if (defined($self->{PIDFILE})) {
            open FILE, "> $self->{PIDFILE}" || $self->logger("PID file save error: $!");
            print FILE "$$\n";
            close FILE;
        }
        
        # broadcast address
        $self->{ADDR_BCAST} = sockaddr_in($self->{CLIENT_PORT}, INADDR_BROADCAST);# sockaddr_in($CLIENT_PORT, inet_aton('255.255.255.255'))
        # set mirror address if defimed
        if (defined($self->{MIRROR})) {$self->{ADDR_MIRROR} = sockaddr_in($self->{SERVER_PORT}, inet_aton($self->{MIRROR}));} # traff mirroring
        # open listening socket
        socket($self->{SOCKET_RCV}, PF_INET, SOCK_DGRAM, getprotobyname('udp')) || die "Socket creation error: $@\n";
        bind($self->{SOCKET_RCV}, sockaddr_in($self->{SERVER_PORT}, inet_aton($self->{BIND_ADDR}))) || die "bind: $!";
        # start threads
        for my $i (1 .. ($self->{THREADS_COUNT} - 1)) {threads->create({ 'context' => 'void' }, sub {$self->request_loop});}
        ### Collect the bits and pieces! ...
        #$_->join foreach threads->list();
        #$_->detach foreach threads->list();
        # and handle request with other threads
        $self->request_loop();
        # delete PID file on exit
        if (defined($self->{PIDFILE})) {unlink($self->{PIDFILE});}
        $self->logger("Main: END!");
    }
    
    sub request_loop {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        my ($buf, $fromaddr, $dhcpreq); # recv data
        my $dbh; # database connect
        my ($t0, $t1, $td); # perfomance data
        my $tid = threads->tid(); # thread ID
        $self->logger("Thread ($tid): START");
        # each thread make its own connection to DB
        # connect($data_source, $username, $password, \%attr)
        # dbi:DriverName:database=database_name;host=hostname;port=port
        until($dbh = DBI->connect("DBI:".$self->{DBDATASOURCE}, $self->{DBLOGIN}, $self->{DBPASS})){
            $self->logger("Thread ($tid): Could not connect to database: $DBI::errstr");
            $self->logger("Thread ($tid): Sleeping 10 sec to retry");
            sleep(10);
        }

        if (defined($dbh) == 0) {
            $self->logger("Could not connect to database: $DBI::errstr");
            $self->thread_exit(1);
        }

        $dbh->{mysql_auto_reconnect} = 1;

        if ($tid != 0) {
            # disable signals receiving on creted threads and set handler for KILL signal
            my $sigset = POSIX::SigSet->new(SIGINT, SIGTERM, SIGHUP);    # define the signals to block
            my $old_sigset = POSIX::SigSet->new;        # where the old sigmask will be kept
            unless (defined sigprocmask(SIG_BLOCK, $sigset, $old_sigset)) {die "Could not unblock SIGINT\n";}

            $SIG{KILL} = sub {
                $self->logger("Thread ($tid): END by sig handler");
                $dbh->disconnect;
                $self->stop();
                $self->thread_exit(0);
            };
        }

        while ($self->{RUNNING} == 1) {
            $buf = undef;
#            $self->logger("RUNNING: $self->{RUNNING}") if ($self->{DEBUG} > 1);

            eval {
#                $self->logger("RUNNING: $self->{RUNNING}") if ($self->{DEBUG} > 1);
                # catch fatal errors
                # receive packet
                $fromaddr = recv($self->{SOCKET_RCV}, $buf, 16384, 0) || $self->logger("Thread ($tid) recv err: $!");

                next if ($!); # continue loop if an error occured

                # filter to small packets
                next if (length($buf) < 236); # 300

                if ($self->{DEBUG} > 0) {
                    $t0 = Benchmark->new;
                }

                # parce data to dhcp structes
                $dhcpreq = Net::DHCP::Packet->new($buf);

                # filter bad params in head
                next if ($dhcpreq->op() != BOOTREQUEST || $dhcpreq->isDhcp() == 0);
                next if ($dhcpreq->htype() != HTYPE_ETHER || $dhcpreq->hlen() != 6);

                # bad DHCP message!
                next if (defined($dhcpreq->getOptionRaw(DHO_DHCP_MESSAGE_TYPE())) == 0);

                # Is message for us?
                next if (defined($dhcpreq->getOptionRaw(DHO_DHCP_SERVER_IDENTIFIER())) && $dhcpreq->getOptionValue(DHO_DHCP_SERVER_IDENTIFIER()) ne $self->{DHCP_SERVER_ID});

                # RRAS client, ignory them
                next if (defined($dhcpreq->getOptionRaw(DHO_USER_CLASS())) && $dhcpreq->getOptionRaw(DHO_USER_CLASS()) eq "RRAS.Microsoft");

                # send duplicate of received packet to mirror
                if (defined($self->{ADDR_MIRROR})) {
                    send($self->{SOCKET_RCV}, $buf, 0, $self->{ADDR_MIRROR}) || $self->logger("send mirr error: $!");
                }

                # print received packed
                if ($self->{DEBUG} > 0) {
                    my ($port, $addr) = unpack_sockaddr_in($fromaddr);
                    my $ipaddr = inet_ntoa($addr);
                    # change hw addr format
                    my $mac = $self->FormatMAC(substr($dhcpreq->chaddr(), 0, (2 * $dhcpreq->hlen())));
                    $self->logger("Thread $tid: Got a packet src = $ipaddr:$port mac = $mac length = " . length($buf));
                    $self->logger($dhcpreq->toString()) if ($self->{DEBUG} > 1);
                }

                $self->db_log_detailed($dbh, $dhcpreq);

                # handle packet
                my $type = $dhcpreq->getOptionValue(DHO_DHCP_MESSAGE_TYPE());
                if ($type == DHCPDISCOVER) {$self->handle_discover($dbh, $fromaddr, $dhcpreq);}#-> DHCPOFFER
                elsif ($type == DHCPREQUEST) {$self->handle_request($dbh, $fromaddr, $dhcpreq);}#-> DHCPACK/DHCPNAK
                elsif ($type == DHCPDECLINE) {$self->handle_decline($dbh, $fromaddr, $dhcpreq);}
                elsif ($type == DHCPRELEASE) {$self->handle_release($dbh, $fromaddr, $dhcpreq);}
                elsif ($type == DHCPINFORM) {$self->handle_inform($dbh, $fromaddr, $dhcpreq);}#-> DHCPACK
                else {}

                if ($self->{DEBUG} > 0) {
                    $t1 = Benchmark->new;
                    $td = timediff($t1, $t0);
                    $self->logger("Thread $tid: the code took: " . timestr($td));
                }
            }; # end of 'eval' blocks
            if ($@) {
                $self->logger("Thread $tid: Caught error in main loop: $@");
            }
        }

        $dbh->disconnect;

        $self->thread_exit(0);
    }
    
    sub thread_exit($) {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        my $tid = threads->tid(); # thread ID

        $self->logger("Thread ($tid): END code: " . $_[0]);

        threads->exit($_[0]) if threads->can('exit');
        exit($_[0]);
    }
    
    sub send_reply {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $fromaddr = $_[0];
        #my $dhcpreq = $_[1];
        #my $dhcpresp = $_[2];
        my ($dhcpresppkt, $toaddr);
        # add last!!!!
        if (defined($_[1]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()))) {$_[2]->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $_[1]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()));}
        $dhcpresppkt = $_[2]->serialize();

        if ($_[1]->giaddr() eq '0.0.0.0') {
            # client local, not relayed
            if ($_[2]->DHO_DHCP_MESSAGE_TYPE() == DHCPNAK) {$toaddr = $self->{ADDR_BCAST};} # allways broadcast DHCPNAK
            else {
                if ($_[1]->ciaddr() eq '0.0.0.0') {
                    # ALL HERE NON RFC 2131 4.1 COMPLIANT!!!
                    # perl can not send to hw addr unicaset with ip 0.0.0.0, and we send broadcast
                    if ($_[1]->flags() == 0 || 1) {
                        # send unicast XXXXXXXXX - flags ignored!
                        # here we mast send unicast to hw addr, ip 0.0.0.0
                        my ($port, $addr) = unpack_sockaddr_in($_[0]);
                        my $ipaddr = inet_ntoa($addr);

                        if ($ipaddr eq '0.0.0.0') {$toaddr = $self->{ADDR_BCAST};}
                        else {$toaddr = sockaddr_in($self->{CLIENT_PORT}, $addr);} # giaddr and ciaddr is zero but we know ip addr from received packet
                    }
                    else {$toaddr = $self->{ADDR_BCAST};} # only this comliant to rfc 2131 4.1
                }
                else {$toaddr = sockaddr_in($self->{CLIENT_PORT}, $_[1]->ciaddrRaw());} # client have IP addr, send unicast
            }
        }
        else {# send to relay
            $toaddr = sockaddr_in($self->{SERVER_PORT}, $_[1]->giaddrRaw());
        }
        send($self->{SOCKET_RCV}, $dhcpresppkt, 0, $toaddr) || $self->logger("send error: $!");

        if ($self->{DEBUG} > 1) {
            my ($port, $addr) = unpack_sockaddr_in($toaddr);
            my $ipaddr = inet_ntoa($addr);
            $self->logger("Sending response to = $ipaddr:$port length = " . length($dhcpresppkt));
        }

        # send copy of packet to mirror, if specified
        if (defined($self->{ADDR_MIRROR})) {
            send($self->{SOCKET_RCV}, $dhcpresppkt, 0, $self->{ADDR_MIRROR}) || $self->logger("send mirr error: $!");
        }
    }

    sub GenDHCPRespPkt {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dhcpreq = $_[0];

        my $dhcpresp = Net::DHCP::Packet->new(Op => BOOTREPLY(),
            Htype                           => $_[0]->htype(),
            Hlen                            => $_[0]->hlen(),
            # Hops                          => $_[0]->hops(), # - not copyed in responce
            Xid                             => $_[0]->xid(),
            Secs                            => $_[0]->secs(),
            Flags                           => $_[0]->flags(),
            Ciaddr                          => $_[0]->ciaddr(),
            #Yiaddr                         => '0.0.0.0',
            Siaddr                          => $_[0]->siaddr(),
            Giaddr                          => $_[0]->giaddr(),
            Chaddr                          => $_[0]->chaddr(),
            DHO_DHCP_MESSAGE_TYPE()         => DHCPACK, # must be owerwritten
            DHO_DHCP_SERVER_IDENTIFIER()    => $self->{DHCP_SERVER_ID}
        );
        return ($dhcpresp);
    }
    
    sub BuffToHEX($) {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        my $buf = shift;
        $buf =~ s/(.)/sprintf("%02x", ord($1))/eg;
        return ($buf);
    }

    sub unpackRelayAgent(%) {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        my @SubOptions = @_;
        my $buf;

        for (my $i = 0; defined($SubOptions[$i]); $i += 2) {
            $buf .= "($SubOptions[$i])=" . $self->BuffToHEX($SubOptions[($i + 1)]) . ', ';
        }

        return ($buf);
    }

    sub GetRelayAgentOptions($$$$$$) {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dhcpreq = $_[0];
        #my $dhcp_opt82_vlan_id = $_[1];
        #my $dhcp_opt82_unit_id = $_[2];
        #my $dhcp_opt82_port_id = $_[3];
        #my $dhcp_opt82_chasis_id = $_[4];
        #my $dhcp_opt82_subscriber_id = $_[5];
        my @RelayAgent;
        # Set return values.
        $_[1] = $_[2] = $_[3] = $_[4] = $_[5] = '';
        # no options, return
        return(0) if (defined($_[0]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS())) == 0);

        @RelayAgent = $_[0]->decodeRelayAgent($_[0]->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()));
        $self->logger("RelayAgent: " . @RelayAgent);

        for (my $i = 0; defined($RelayAgent[$i]); $i += 2) {
            if ($RelayAgent[$i] == 1) {
                    # Circuit ID
                    $self->logger("RelayAgent Circuit ID: " . $RelayAgent[($i + 1)]);
                    next if (length($RelayAgent[($i + 1)]) < 4);
                    # first bytes must be: 00 04
                    #$_[1] = unpack('n', substr($RelayAgent[($i + 1)], -4, 2)); # may be 's'
                    $RelayAgent[($i + 1)] =~ /(\d+)(?=\ )/;
                    $_[1] = $1;
                    $self->logger("RelayAgent VLan: " . $_[1]);
                    #$_[2] = unpack('C', substr($RelayAgent[($i + 1)], -2, 1));
                    $RelayAgent[($i + 1)] =~ /(\d+)(?=\/\d+:)/;
                    $_[2] = $1;
                    $self->logger("RelayAgent Unit: " . $_[2]);
                    #$_[3] = unpack('C', substr($RelayAgent[($i + 1)], -1, 1));
                    $RelayAgent[($i + 1)] =~ /(\d+)(?=:)/;
                    $_[3] = $1;
                    $self->logger("RelayAgent Port: " . $_[3]);
                }
            elsif ($RelayAgent[$i] == 2) {
                    # Remote ID
                    next if (length($RelayAgent[($i + 1)]) < 6);
                    # first bytes must be: 00 06 or 01 06 or 02 xx
                    # first digit - format/data type, second - len
                    $_[4] = $self->FormatMAC(unpack("H*", substr($RelayAgent[($i + 1)], - 6, 6)));
                    $self->logger("RelayAgent 4: " . $_[4]);
                    # 02 xx - contain vlan num, undone
                }
            elsif ($RelayAgent[$i] == 6) {
                    # Subscriber ID
                    $_[5] = $RelayAgent[($i + 1)];
                    $self->logger("RelayAgent 5: " . $_[5]);
                }
            else {}
        }

        return (1);
    }

    sub FormatMAC {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        $_[0] =~ /([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})/i;
        return (lc(join(':', $1, $2, $3, $4, $5, $6)));
    }

    sub subnetBits {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        my $m = unpack("N", pack("C4", split(/\./, $_[0])));
        my $v = pack("L", $m);
        my $bcnt = 0;

        foreach (0 .. 31) {
            if (vec($v, $_, 1) == 1) {$bcnt++;}
        }

        return ($bcnt);
    }
    
    sub mk_classless_routes_bin_mask {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $net = $_[0];
        #my $mask = $_[1];
        #my $gw = $_[2];
        return ($self->mk_classless_routes_bin_prefixlen($_[0], $self->subnetBits($_[1]), $_[2]));
    }

    sub mk_classless_routes_bin_prefixlen {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $net = $_[0];
        #my $prefixlen = $_[1];
        #my $gw = $_[2];
        my $str;
        $str = pack('C', $_[1]);

        if ($_[1] > 0) {
            my ($s1, $s2, $s3, $s4) = split(/\./, $_[0]);
            $str .= pack('C', $s1);
            $str .= pack('C', $s2) if ($_[1] > 8);
            $str .= pack('C', $s3) if ($_[1] > 16);
            $str .= pack('C', $s4) if ($_[1] > 24);
        }

        $str .= pack('CCCC', split(/\./, $_[2]));

        return ($str);
    }
    
    sub handle_discover {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $fromaddr  = $_[1];
        #my $dhcpreq = $_[2];
        my ($dhcpresp);
        $dhcpresp = $self->GenDHCPRespPkt($_[2]);
        $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPOFFER);

        if ($self->db_get_requested_data($_[0], $_[2], $dhcpresp, $_[1]) == 1) {
            $self->send_reply($_[1], $_[2], $dhcpresp);
            $self->db_lease_offered($_[0], $_[2], $dhcpresp);
        }
        else {# if AUTO_CONFIGURE (116) supported - send disable generate link local addr
            if (defined($_[2]->getOptionRaw(DHO_AUTO_CONFIGURE))
                && $_[2]->getOptionValue(DHO_AUTO_CONFIGURE()) != 0) {
                $dhcpresp->addOptionValue(DHO_AUTO_CONFIGURE(), 0);
                $self->send_reply($_[1], $_[2], $dhcpresp);
            }
        }
    }
    
    sub handle_request {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $fromaddr  = $_[1];
        #my $dhcpreq = $_[2];
        my ($dhcpresp);
        $dhcpresp = $self->GenDHCPRespPkt($_[2]);

        if ($self->db_get_requested_data($_[0], $_[2], $dhcpresp, $_[1]) == 1) {
            if ((defined($_[2]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) &&
                $_[2]->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS()) ne $dhcpresp->yiaddr()) ||
                (defined($_[2]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) == 0
                    && $_[2]->ciaddr() ne $dhcpresp->yiaddr())) {
                # NAK if requested addr not equal IP addr in DB
                $dhcpresp->ciaddr('0.0.0.0');
                $dhcpresp->yiaddr('0.0.0.0');
                $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPNAK);
                $self->db_lease_nak($_[0], $_[2]);
            }
            else {
                $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);
                $self->db_lease_success($_[0], $_[2]);
            }

            $self->send_reply($_[1], $_[2], $dhcpresp);
        }
    }
    
    sub handle_decline {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $fromaddr  = $_[1];
        #my $dhcpreq = $_[2];
        $self->db_lease_decline($_[0], $_[2]);
    }
    
    sub handle_release {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $fromaddr  = $_[1];
        #my $dhcpreq = $_[2];
        $self->db_lease_release($_[0], $_[2]);
    }
    
    sub handle_inform {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $fromaddr  = $_[1];
        #my $dhcpreq = $_[2];
        my ($dhcpreqparams, $dhcpresp);
        $dhcpresp = $self->GenDHCPRespPkt($_[2]);
        $dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);

        if ($self->db_get_requested_data($_[0], $_[2], $dhcpresp, $_[1]) == 0) {
            $dhcpreqparams = $_[2]->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST());
            $self->static_data_to_reply($dhcpreqparams, $dhcpresp);
        }

        $self->send_reply($_[1], $_[2], $dhcpresp);
    }
    
    sub static_data_to_reply {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dhcpreqparams = $_[0];
        #my $dhcpresp = $_[1];
        # do not add params if not requested
        return() if (defined($_[0]) == 0);
        if (index($_[0], DHO_ROUTER_DISCOVERY()) != - 1) {$_[1]->addOptionValue(DHO_ROUTER_DISCOVERY(), 0);}
        if (index($_[0], DHO_NTP_SERVERS()) != - 1) {$_[1]->addOptionValue(DHO_NTP_SERVERS(), '8.8.8.8 8.8.8.8');}
        if (index($_[0], DHO_NETBIOS_NODE_TYPE()) != - 1) {$_[1]->addOptionValue(DHO_NETBIOS_NODE_TYPE(), 8);} # H-Node
        # Option 43 must be last for Windows XP proper work
        # https://support.microsoft.com/en-us/kb/953761
        if (index($_[0], DHO_VENDOR_ENCAPSULATED_OPTIONS()) != - 1) {
            # 001 - NetBIOS over TCP/IP (NetBT): 00000002 (2) - disabled
            # 002 - Release DHCP Lease on Shutdown: 00000001 (1) - enabled
            # 255 - END
            $_[1]->addOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS(), "\x01\x04\x00\x00\x00\x02\x02\x04\x00\x00\x00\x01\xff");
        }
    }
    
    sub db_get_requested_data {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreq = $_[1];
        #my $dhcpresp = $_[2];
        #my $fromaddr = $_[3];
        my ($port, $addr) = unpack_sockaddr_in($_[3]);
        my $ipaddr = inet_ntoa($addr);
        my ($mac, $sth, $dhcpreqparams, $result);
        my ($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        # change hw addr format
        $mac = $self->FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
        $dhcpreqparams = $_[1]->getOptionValue(DHO_DHCP_PARAMETER_REQUEST_LIST());
        $sth = $_[0]->prepare($self->{get_requested_data});

        if ($self->{DEBUG} > 1) {
            $self->logger("Got a packet src = $ipaddr:$port");
            $self->logger("SQL: $self->{get_requested_data}", $mac, $ipaddr);
        }

        $sth->execute($mac, $ipaddr);

        if ($sth->rows()) {
            $result = $sth->fetchrow_hashref();
            $_[2]->yiaddr($result->{ip});
            $self->db_data_to_reply($result, $dhcpreqparams, $_[2]);
            $self->db_get_routing($_[0], $dhcpreqparams, $result->{subnet_id}, $_[2]);
            $self->static_data_to_reply($dhcpreqparams, $_[2]);
            $sth->finish();
            return (1);
        }

        if ($self->GetRelayAgentOptions($_[1], $dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id,
            $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id)) {
            # try work as traditional DHCP: find scope by opt82 info, then give some free addr

            if ($dhcp_opt82_chasis_id ne '') {
                $sth = $_[0]->prepare($self->{get_requested_data_opt82});
                $self->logger("SQL: $self->{get_requested_data_opt82}", $dhcp_opt82_vlan_id) if ($self->{DEBUG} > 1);
                $sth->execute($dhcp_opt82_vlan_id);

                if ($sth->rows()) {
                    $result = $sth->fetchrow_hashref();
                    $self->db_data_to_reply($result, $dhcpreqparams, $_[2]);
                    $self->db_get_routing($_[0], $dhcpreqparams, $result->{subnet_id}, $_[2]);
                    $self->static_data_to_reply($dhcpreqparams, $_[2]);
                    $sth->finish();
                    return (1);
                }
            }
        }

        $sth->finish();

        return (0);
    }
    
    sub db_data_to_reply {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $result = $_[0];
        #my $dhcpreqparams = $_[1];
        #my $dhcpresp = $_[2];
        if (defined($_[0]->{dhcp_lease_time})) {
            $_[2]->addOptionValue(DHO_DHCP_LEASE_TIME(), $_[0]->{dhcp_lease_time});

            # function (typically 50%) of the full configured duration (or lease time) for a client's lease
            if (defined($_[0]->{dhcp_renewal})) {
                $_[2]->addOptionValue(DHO_DHCP_RENEWAL_TIME(), $_[0]->{dhcp_renewal});
                #} else {
                #	$_[2]->addOptionValue(DHO_DHCP_RENEWAL_TIME(), ($_[0]->{dhcp_lease_time}/2));
            }

            # function (typically 87.5%) of the full configured duration (or lease time) for a client's lease
            if (defined($_[0]->{dhcp_rebind_time})) {
                $_[2]->addOptionValue(DHO_DHCP_REBINDING_TIME(), $_[0]->{dhcp_rebind_time});
                #} else {
                #	$_[2]->addOptionValue(DHO_DHCP_REBINDING_TIME(), ($_[0]->{dhcp_lease_time}*7/8));
            }
        }

        # do not add params if not requested
        return() if (defined($_[1]) == 0);

        if (index($_[1], DHO_SUBNET_MASK()) != - 1 && defined($_[0]->{mask})) {$_[2]->addOptionValue(DHO_SUBNET_MASK(), $_[0]->{mask});}
        if (index($_[1], DHO_ROUTERS()) != - 1 && defined($_[0]->{gateway})) {$_[2]->addOptionValue(DHO_ROUTERS(), $_[0]->{gateway});}
        if (index($_[1], DHO_DOMAIN_NAME_SERVERS()) != - 1 && defined($_[0]->{dns1})) {$_[2]->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), "$_[0]->{dns1} $_[0]->{dns2}");}
        if (index($_[1], DHO_HOST_NAME()) != - 1 && defined($_[0]->{hostname})) {$_[2]->addOptionValue(DHO_HOST_NAME(), $_[0]->{hostname});}
        if (index($_[1], DHO_DOMAIN_NAME()) != - 1 && defined($_[0]->{domain})) {$_[2]->addOptionValue(DHO_DOMAIN_NAME(), $_[0]->{domain});}
    }
    
    sub db_get_routing {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreqparams = $_[1];
        #my $subnet_id = $_[2];
        #my $dhcpresp = $_[3];
        my ($sth, $opt33Enbled, $optClasslessRoutesCode);
        # do not add routes if not requested
        return() if (defined($_[1]) == 0);
        $opt33Enbled = index($_[1], DHO_STATIC_ROUTES());
        if ($opt33Enbled == - 1) {
            $opt33Enbled = undef;
        }

        $optClasslessRoutesCode = index($_[1], 121);
        if ($optClasslessRoutesCode == - 1) {
            $optClasslessRoutesCode = index($_[1], 249); # MSFT
            if ($optClasslessRoutesCode == - 1) {
                $optClasslessRoutesCode = undef;
            }
            else {
                $opt33Enbled = undef;
                $optClasslessRoutesCode = 249;
            }
        }
        else {
            $opt33Enbled = undef;
            $optClasslessRoutesCode = 121;
        }

        if (defined($opt33Enbled) == 0 && defined($optClasslessRoutesCode) == 0) {
            # nothink to do, return
            return ();
        }

        $sth = $_[0]->prepare($self->{get_routing});
        $self->logger("SQL: $self->{get_routing}") if ($self->{DEBUG} > 1);
        $sth->execute();
        if ($sth->rows()) {
            my $ref;
            my $row;
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
                if (defined($optClasslessRoutesCode)) {
                    $opt_classless_routes_data .= $self->mk_classless_routes_bin_mask(@$row[0], @$row[1], @$row[2]);
                }
            }

            if (defined($opt33_data)) {# add option
                $_[3]->addOptionRaw(DHO_STATIC_ROUTES(), $opt33_data);
            }

            if (defined($opt_classless_routes_data)) {# add option
                $_[3]->addOptionRaw($optClasslessRoutesCode, $opt_classless_routes_data);
            }
        }
        $sth->finish();
    }
    
    sub db_lease_offered {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreq = $_[1];
        #my $dhcpresp = $_[2];
        my ($mac, $sth, $yaddr);
        # change hw addr format
        $mac = $self->FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
        $yaddr = $_[2]->yiaddr();
        $sth = $_[0]->prepare($self->{lease_offered});

        $self->logger("SQL: $self->{lease_offered}") if ($self->{DEBUG} > 1);
        $sth->execute();
        $sth->finish();

        return (0);
    }
    
    sub db_lease_nak {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreq = $_[1];
        my ($mac, $sth);
        # change hw addr format
        $mac = $self->FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
        $sth = $_[0]->prepare($self->{lease_nak});
        $self->logger("SQL: $self->{lease_nak}") if ($self->{DEBUG} > 1);
        $sth->execute();
        $sth->finish();

        return (0);
    }
    
    sub db_lease_decline {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreq = $_[1];
        my ($mac, $sth);
        my ($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        my ($client_ip, $gateway_ip, $client_ident, $requested_ip, $hostname, $dhcp_vendor_class, $dhcp_user_class);
        # change hw addr format
        $mac = $self->FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
        $self->GetRelayAgentOptions($_[1],$dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        $client_ip = $_[1]->ciaddr;
        $gateway_ip = $_[1]->giaddr;
        $client_ident = defined($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) ? $self->BuffToHEX($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) : '';
        $requested_ip = defined($_[1]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) ? $_[1]->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS()) : '';
        $hostname = defined($_[1]->getOptionRaw(DHO_HOST_NAME())) ? $_[1]->getOptionValue(DHO_HOST_NAME()) : '';
        $dhcp_vendor_class = defined($_[1]->getOptionRaw(DHO_VENDOR_CLASS_IDENTIFIER())) ? $_[1]->getOptionValue(DHO_VENDOR_CLASS_IDENTIFIER()) : '';
        $dhcp_user_class = defined($_[1]->getOptionRaw(DHO_USER_CLASS())) ? $_[1]->getOptionRaw(DHO_USER_CLASS()) : '';
        $sth = $_[0]->prepare($self->{lease_decline});
        $self->logger("SQL: $self->{lease_decline}") if ($self->{DEBUG} > 1);
        $sth->execute();
        $sth->finish();

        return (0);
    }
    
    sub db_lease_release {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreq = $_[1];
        my ($mac, $sth);
        # change hw addr format
        $mac = $self->FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
        $sth = $_[0]->prepare($self->{lease_release});
        $self->logger("SQL: $self->{lease_release}") if ($self->{DEBUG} > 1);
        $sth->execute();
        $sth->finish();

        return (0);
    }
    
    sub db_lease_success {
        my($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreq = $_[1];
        my ($mac, $sth, $result);
        my ($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id, $dhcp_vendor_class, $dhcp_user_class);
        # change hw addr format
        $mac = $self->FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
        $self->GetRelayAgentOptions($_[1], $dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        $dhcp_vendor_class = defined($_[1]->getOptionRaw(DHO_VENDOR_CLASS_IDENTIFIER())) ? $_[1]->getOptionValue(DHO_VENDOR_CLASS_IDENTIFIER()) : '';
        $dhcp_user_class = defined($_[1]->getOptionRaw(DHO_USER_CLASS())) ? $_[1]->getOptionRaw(DHO_USER_CLASS()) : '';
        $sth = $_[0]->prepare($self->{lease_success});
        $self->logger("SQL: $self->{lease_success}") if ($self->{DEBUG} > 1);
        $sth->execute();
        $sth->finish();
    }
    
    sub db_log_detailed {
        my ($self) = shift;
        $self->logger("Function: " . (caller(0))[3]) if ($self->{DEBUG} > 1);
        #my $dbh = $_[0];
        #my $dhcpreq = $_[1];
        my ($mac, $sth);
        my ($dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        my ($client_ip, $gateway_ip, $client_ident, $requested_ip, $hostname, $dhcp_vendor_class, $dhcp_user_class);
        # change hw addr format
        $mac = $self->FormatMAC(substr($_[1]->chaddr(), 0, (2 * $_[1]->hlen())));
        $self->GetRelayAgentOptions($_[1], $dhcp_opt82_vlan_id, $dhcp_opt82_unit_id, $dhcp_opt82_port_id, $dhcp_opt82_chasis_id, $dhcp_opt82_subscriber_id);
        $client_ip = $_[1]->ciaddr;
        $gateway_ip = $_[1]->giaddr;
        $client_ident = defined($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) ? $self->BuffToHEX($_[1]->getOptionRaw(DHO_DHCP_CLIENT_IDENTIFIER())) : '';
        $requested_ip = defined($_[1]->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) ? $_[1]->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS()) : '';
        $hostname = defined($_[1]->getOptionRaw(DHO_HOST_NAME())) ? $_[1]->getOptionValue(DHO_HOST_NAME()) : '';
        $dhcp_vendor_class = defined($_[1]->getOptionRaw(DHO_VENDOR_CLASS_IDENTIFIER())) ? $_[1]->getOptionValue(DHO_VENDOR_CLASS_IDENTIFIER()) : '';
        $dhcp_user_class = defined($_[1]->getOptionRaw(DHO_USER_CLASS())) ? $_[1]->getOptionRaw(DHO_USER_CLASS()) : '';

        $sth = $_[0]->prepare($self->{log_detailed});
        $sth->execute();
        $sth->finish();
    }

}

1;
