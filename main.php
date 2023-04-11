<?php

# Define your settings here.
define('WAN_IP', '8.8.8.8');
define('WAN_INTERFACE_NAME', 'enp7s0');
define('HOST_LAN_IP', "192.168.0.1");
define('LAN_INTERFACE_NAME', "enp7s1");



class IptablesGenerator implements Stringable
{
    private string $m_wanIp;
    private string $m_wanInterfaceName;
    private string $m_hostLanIp;
    private string $m_lanInterfaceName;

    private array $m_allocatedHostPorts; // ports on the host that have been allocated to some rule.
    private array $m_rules; // array of string rules to put in the output.



    public function __construct(string $wanIp, string $wanInterfaceName, string $hostLanIp, string $lanInterfaceName)
    {
        $this->m_wanInterfaceName = $wanInterfaceName;
        $this->m_wanIp = $wanIp;
        $this->m_hostLanIp = $hostLanIp;
        $this->m_lanInterfaceName = $lanInterfaceName;

        $this->m_rules = [];
        $this->m_allocatedHostPorts = [];
    }


    public function createPortForwardingRule(
        int $incomingPort,
        string $desiredInternalServerLanIp,
        int $desiredPort,
        string $protocol="tcp"
    ) : void
    {
        $this->allocatePort($incomingPort, $protocol);

        # Add a rule to accept the connection from the outside world in the first place
        $this->m_rules[] =
            "/sbin/iptables"
            . " --append INPUT"
            . " --in-interface {$this->m_wanInterfaceName}"
            . " --destination {$this->m_wanIp}/32"
            . " --protocol {$protocol}"
            . " --dport {$incomingPort}"
            . " --jump ACCEPT"
            ;

        # Add a NAT rule to transform the incoming ip/port to an outgoing ip/port
        $this->m_rules[] =
            "/sbin/iptables"
            . " --table nat"
            . " --append PREROUTING"
            . " --in-interface {$this->m_wanInterfaceName}"
            . " --destination {$this->m_wanIp}/32"
            . " --protocol {$protocol}"
            . " --dport {$incomingPort}"
            . " --jump DNAT"
            . " --to-destination {$desiredInternalServerLanIp}:{$desiredPort}"
            ;

        # Add a rule to tell iptables to allow forwarding in this scenario.
        $this->m_rules[] =
            "/sbin/iptables"
            . " --append FORWARD"
            . " --protocol {$protocol}"
            . " --destination {$desiredInternalServerLanIp}"
            . " --dport {$desiredPort}"
            . " --match state "
            . " --state NEW,ESTABLISHED,RELATED"
            . " --jump ACCEPT"
            ;
    }


    /**
     * Creates a port forward range, instead of a single port.
     */
    public function createPortForwardingRuleRange(
        string $desiredInternalServerLanIp,
        int $startPort,
        int $endPort,
        string $protocol="tcp"
    )
    {
        $this->allocatePortRange($startPort, $endPort, $protocol);

        # Add a rule to accept the connection from the outside world in the first place
        $this->m_rules[] =
            "/sbin/iptables"
            . " --append INPUT"
            . " --in-interface {$this->m_wanInterfaceName}"
            . " --destination {$this->m_wanIp}/32"
            . " --protocol {$protocol}"
            . " --dport {$startPort}:{$endPort}"
            . " --jump ACCEPT";

        # Add a NAT rule to transform the incoming ip/port to an outgoing ip/port
        $this->m_rules[] =
            "/sbin/iptables"
            . " --table nat"
            . " --append PREROUTING"
            . " --in-interface {$this->m_wanInterfaceName}"
            . " --destination {$this->m_wanIp}/32"
            . " --protocol {$protocol}"
            . " --dport {$startPort}:{$endPort}"
            . " --jump DNAT"
            . " --to-destination {$desiredInternalServerLanIp}:{$startPort}-{$endPort}";

        # Add a rule to tell iptables to allow forwarding in this scenario.
        $this->m_rules[] =
            "/sbin/iptables" .
            " --append FORWARD" .
            " --protocol {$protocol}" .
            " --destination {$desiredInternalServerLanIp}" .
            " --dport {$startPort}:{$endPort}" .
            " --match state " .
            " --state NEW,ESTABLISHED,RELATED" .
            " --jump ACCEPT";
    }


    /**
     * Open up a port on this server to the outside world. This is part of
     * forwarding onto other servers, but for this server.
     * @param int $port
     * @param string $protocol
     * @return void
     */
    public function openPort(int $port, string $protocol="tcp") : void
    {
        $this->allocatePort($port, $protocol);

        $this->m_rules[] =
            "/sbin/iptables"
            . " --append INPUT "
            . " --protocol {$protocol}"
            . " --in-interface {$this->m_wanInterfaceName}"
            . " --destination {$this->m_wanIp}/32"
            . " --dport {$port}"
            . " --jump ACCEPT"
            ;
    }


    public function __toString() : string
    {
        $commands[] = "#!/bin/bash";

        # reset by deleting all rules, and then all chains
        $commands[] = "/sbin/iptables --flush";
        $commands[] = "/sbin/iptables --delete-chain";

        # Setting default filter policy
        # Drop any incoming packets unless a subsequent rule whitelists them
        $commands[] = "/sbin/iptables --policy INPUT DROP";
        $commands[] = "/sbin/iptables --policy OUTPUT ACCEPT";
        $commands[] = "/sbin/iptables --policy FORWARD DROP";

        # Accept all traffic coming in and out of the loopback interface.
        $commands[] = "/sbin/iptables --append INPUT --in-interface lo --jump ACCEPT";
        $commands[] = "/sbin/iptables --append OUTPUT --out-interface lo --jump ACCEPT";

        # Allow any already established connections to keep carrying on.
        $commands[] =
            "/sbin/iptables"
            . " --append INPUT"
            . " --match state"
            . " --state RELATED,ESTABLISHED"
            . " --jump ACCEPT"
            ;

        # Allow any already established connections to keep carrying on forwarding
        $commands[] =
            "/sbin/iptables"
            . " --append FORWARD"
            . " --match state"
            . " --state RELATED,ESTABLISHED"
            . " --jump ACCEPT"
            ;

        # Add a rule to the input chain that the firewall should accept all packets
        # coming in on the internal lan interface (e.g. dont filter block)
        $commands[] =
            "/sbin/iptables"
            . " --append INPUT" # same as -I
            . " --in-interface {$this->m_lanInterfaceName}"
            . " --jump ACCEPT"
            ;

        # Accept the forwarding of all packets that came in on the internal private network for KVM guests.
        # This should go last
        $commands[] =
            "/sbin/iptables"
            . " --append FORWARD"
            . " --in-interface {$this->m_lanInterfaceName}"
            . " --jump ACCEPT"
            ;

        $commands = [...$commands, ...$this->m_rules];

        # All packets being forwarded out of this server to the internet should look
        #like they are coming from this server.
        $commands[] =
            "/sbin/iptables"
            . " --table nat"
            . " --append POSTROUTING"
            . " --out-interface {$this->m_wanInterfaceName}"
            . " --jump MASQUERADE"
            ;

        return implode(PHP_EOL, $commands) . PHP_EOL;
    }


    /**
     * Allocate a port so that it cannot be re-used by something else (clash)
     * @param int $port
     * @throws Exception - if the port has already been allocated by something else.
     */
    private function allocatePort(int $port, string $protocol = "tcp") : void
    {
        if (!in_array($protocol, ["tcp", "udp"]))
        {
            throw new Exception("Unrecognized protocol: {$protocol}");
        }

        if (isset($this->m_allocatedHostPorts[$port]))
        {
            if (isset($this->m_allocatedHostPorts[$port][$protocol]))
            {
                throw new Exception("Port {$port} with protocol {$protocol} has already been allocated.");
            }
            else
            {
                $this->m_allocatedHostPorts[$port][$protocol] = 1;
            }
        }
        else
        {
            $this->m_allocatedHostPorts[$port] = array();
            $this->m_allocatedHostPorts[$port][$protocol] = 1;
        }
    }


    /**
     * Allocate a range of ports.
     * @param int $minPort
     * @param int $maxPort
     */
    private function allocatePortRange(int $minPort, int $maxPort, string $protocol = "tcp") : void
    {
        for ($i = $minPort; $i<=$maxPort; $i++)
        {
            $this->allocatePort($i, $protocol);
        }
    }
}


$iptables = new IptablesGenerator(
    WAN_IP,
    WAN_INTERFACE_NAME,
    HOST_LAN_IP,
    LAN_INTERFACE_NAME
);

$iptables->openPort(22); // allow SSH in remotely
$iptables->openPort(80); // allow http connections to this server for reverse proxy
$iptables->openPort(443); // allow https connections to this server for reverse proxy


# Example internal server to forward onto. This will forward incoming requests on port 2222 to the LAN guest
# at 192.168.0.2 on port 22
$iptables->createPortForwardingRule(2222, "192.168.0.2", 22);


# Output the rules. You will need to manually run these on your server, or perhaps configure it to run these on startup.
print $iptables;


