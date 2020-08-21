from mininet.topo import Topo
from mininet.link import TCLink 

# Keep this class name the same in your topologies!!
class AdvNet( Topo ):

    def __init__( self ):
        Topo.__init__( self )

        # Add hosts and switches
        host1 = self.addHost( 'h1' )
        host2 = self.addHost( 'h2' )
        host3 = self.addHost( 'h3' )
        host4 = self.addHost( 'h4' )
        host5 = self.addHost( 'h5' )
        host6 = self.addHost( 'h6' )
        
        switch1 = self.addSwitch( 's1' )
        switch2 = self.addSwitch( 's2' )
        switch3 = self.addSwitch( 's3' )

        # Add links
        self.addLink( host1, switch1 )
        self.addLink( host2, switch1 )
        self.addLink( host3, switch1 )
        self.addLink( host4, switch3 )
        self.addLink( host5, switch3 )
        self.addLink( host6, switch3 )
        self.addLink( switch1, switch2 )
        self.addLink( switch2, switch3 )


# Keep this part the same for use in the CLI
topos = { 'topology': ( lambda: AdvNet() ) }
