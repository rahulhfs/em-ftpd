module EM::FTPD

  # An eventmachine module for opening a socket for the client to connect
  # to and send a file
  #
  class PassiveSocket < EventMachine::Connection
    include EM::Deferrable
    include BaseSocket

   def self.start(host, control_server)
      EventMachine.start_server(host, 0, SecurePassiveSocket) do |conn|
        if control_server.securedatachannel == true
            conn.set_control_socket(control_server)
            conn.start_tls(:private_key_file => control_server.get_private_key,
              :cert_chain_file => control_server.get_certificate,
              :verify_peer => true)
        else
            control_server.datasocket = conn
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
      return Socket.unpack_sockaddr_in( EM.get_sockname( sig ) ).first
    end

  end

  class SecurePassiveSocket <  EventMachine::Connection
    attr_accessor :control_socket

    def initialize(*args)
        super()
    end

    def ssl_handshake_completed
      if !@control_socket.nil?
        @control_socket.datasocket = self
      end
    end

    def set_control_socket(cs)
       @control_socket = cs
    end
  end

end
