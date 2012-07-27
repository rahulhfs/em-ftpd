module EM::FTPD

  # An eventmachine module for opening a socket for the client to connect
  # to and send a file
  #
  class PassiveSocket < EventMachine::Connection
    include EM::Deferrable
    include BaseSocket
    

    def self.start(host, control_server)
      EventMachine.start_server(host, 0, self) do |conn|
        control_server.datasocket = conn
        if control_server.securedatachannel == true
                  control_server.datasocket.start_tls(:private_key_file => control_server.get_private_key,
            :cert_chain_file => control_server.get_certificate,
            :verify_peer => false)
        end
      end
    end

    # stop the server with signature "sig"
    def self.stop(sig)
      EventMachine.stop_server(sig)
    end

    # return the port the server with signature "sig" is listening on
    #
    def self.get_port(sig)
      Socket.unpack_sockaddr_in( EM.get_sockname( sig ) ).first
    end

    
  end
end
