require 'socket'
require 'timeout'
require 'digest/sha1'

module Listenable
    def listeners() @listeners ||= [] end

    def on(event_name, &block)
        listeners << [event_name, block]
    end

    def emit(event_name, *args)
        listeners.each do |listener|
            if (listener[0] == event_name)
                listener[1].call(*args)
            end
        end
    end

    def emit_thread(event_name, *args)
        listeners.each do |listener|
            if (listener[0] == event_name)
                Thread.new { listener[1].call(*args) }
            end
        end
    end
end

class WebSocket
    include Listenable

    attr_reader :sock_domain, :remote_port, :remote_hostname, :ip, :status

    module Status
        CONNECTING = 0
        OPEN = 1
        CLOSING = 2
        CLOSED = 3
    end

    def initialize(raw_socket)
        @raw_socket = raw_socket
        @sock_domain, @remote_port, @remote_hostname, @ip = raw_socket.peeraddr

        @status = Status::CONNECTING
        self.handshake()
    end

    def handshake()
        http_request = ''
        begin
            Timeout.timeout(5) do
                # Read the HTTP request. We know it's finished when we see a line with nothing but \r\n
                while (line = @raw_socket.gets()) && (line != "\r\n")
                    http_request += line.chomp + "\n"
                end
            end
        rescue Timeout::Error
            return self.close_fail("HTTP Request timeout (5s)")
        end

        return self.close_fail("HTTP Request was empty") if http_request == ""

        # validate request, but only HTTP version, we accept all uris
        matches = http_request.lines[0].match(/^GET (?<uri>\/.*) HTTP\/(?<version>\d\.\d)$/)
        return self.close_fail("HTTP Version must be at least 1.1") if !matches || matches[:version].to_f < 1.1

        # we don't really care what, it just must exist
        matches = http_request.match(/^Host:\s+(?<host>[^:]*)(:(?<port>[1-9]*))?$/)
        return self.close_fail("HTTP Request didn't have a Host header") if !matches || matches[:host] == ""

        # request must have Upgrade header with websocket in it
        matches = http_request.match(/^Upgrade:\s+(?<upgrades>.*)$/)
        return self.close_fail("HTTP Request didn't have websocket Upgrade header") if !matches || !matches[:upgrades].include?("websocket")

        # request must have Connection header with Upgrade in it
        matches = http_request.match(/^Connection:\s+(?<connections>.*)$/)
        return self.close_fail("HTTP Request didn't have Connection header set to Upgrade") if !matches || !matches[:connections].include?("Upgrade")

        # websocket version must be 13
        matches = http_request.match(/^Sec-WebSocket-Version:\s+(?<version>[1-9]+)$/)
        return self.close_fail("HTTP Request websocket version wasn't 13") if !matches || matches[:version].to_i != 13

        # Grab the security key from the headers. If one isn't present, close the connection.
        matches = http_request.match(/^Sec-WebSocket-Key:\s+(?<key>.*)$/)
        return self.close_fail("HTTP Request didn't have websocket key") if !matches || matches[:key] == ""

        response_key = Digest::SHA1.base64digest([matches[:key], '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'].join)

        response = "HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: #{response_key}\r\n\r\n"


        begin
            @raw_socket.write(response)
        rescue Errno::EPIPE
            return self.close_fail("Connection Failed!")
        end

        @status = Status::OPEN
    end

    def recvheader()
        first_byte = @raw_socket.getbyte()
        second_byte =  @raw_socket.getbyte()
        return if first_byte == nil || second_byte == nil

        fin = (first_byte & 0b10000000) >> 7
        opcode = first_byte & 0b00001111
        is_masked = (second_byte & 0b10000000) >> 7

        payload_length = second_byte & 0b01111111
        if payload_length == 126 # next 2 bytes are payload_length
            payload_length = 2.times.map { @raw_socket.getbyte }
        elsif payload_length == 127 # next 4 bytes are payload_length
            payload_length = 4.times.map { @raw_socket.getbyte }
        end

        data = nil

        return self.send_close("Unmasked frame from client to server!") if is_masked == 0

        mask_key = 4.times.map {  @raw_socket.getbyte() }
        maksed_data = payload_length.times.map {  @raw_socket.getbyte() }
        data = maksed_data.each_with_index.map { |byte, i| byte ^ mask_key[i % 4] }

        return fin, opcode, is_masked, payload_length, data
    end

    def recv()
        return if self.closed?

        fin, opcode, is_maksed, payload_length, data = self.recvheader()
        return if data == nil

        # we don't support fragmentation
        return if fin == 0 || opcode == 0

        case opcode
        when 1
            # text frame
            msg = data.pack('C*').force_encoding('utf-8')
            self.emit("message_text", msg)
        when 2
            # binary frame
            msg = data
            self.emit("message_binary", msg)
        when 8
            # close frame
            return self.send_close("Control frame can't be fragmented") if (fin != 1)
            return self.send_close("Control frame can't have payload length greater than 125") if (payload_length > 125)

            if (@status == Status::OPEN && payload_length > 0)
                status_code = data.pack("n")
                msg = data.drop(2).pack('C*').force_encoding('utf-8')

                self.send_close("Closing with Status Code of #{status_code}:\r\n#{msg}")
            else
                self.send_close()
            end
        when 9
            # ping frame
            return self.send_close("Control frame can't be fragmented") if (fin != 1)
            return self.send_close("Control frame can't have payload length greater than 125") if (payload_length > 125)

            # send pong frame
            self.send(1, 9, 0, data)
        when 10
            # pong frame
            return self.send_close("Control frame can't be fragmented") if (fin != 1)
            return self.send_close("Control frame can't have payload length greater than 125") if (payload_length > 125)

            # we don't care about pong frames, so do nothing
        else
            return self.send_close("Unsupported Opcode!")
        end
    end

    def send_text(data)
        self.send(1, 1, 0, data)
    end

    def send_binary(data)
        self.send(1, 2, 0, data)
    end

    def send_close(reason = "")
        return if self.closed?

        reason = reason.slice(0, 125)

        self.send(1, 8, 0, reason)
        @status = Status::CLOSING
    end

    def send(fin, opcode, mask, data = [])
        return if self.closed?
        return if (fin == 0 || opcode == 0 || mask == 1 || @status != Status::OPEN)

        data = data.kind_of?(Array) ? data : data.codepoints()
        payload_length = data.size

        first_byte = fin << 7 | opcode

        if (payload_length < 0x7E)
            second_byte = mask << 7 | payload_length
            output = [first_byte, second_byte].concat(data)
            output = output.pack("CCC#{payload_length}")
        elsif (payloadLength <= 0xFFFF)
            secondByte = mask << 7 | 0x7E
            output = [first_byte, second_byte, payload_length].concat(data)
            output = output.pack("CCnC#{payload_length}")
        elsif payloadLength <= 0x7FFFFFFFFFFFFFFF
            secondByte = mask << 7 | 0x7F
            output = [first_byte, second_byte, payload_length, data]
            output = output.pack("CCNC#{payload_length}")
        end

        @raw_socket.write(output)
    end

    def closed?
        return @raw_socket.closed? || @status == Status::CLOSING || @status == Status::CLOSED
    end

    def close_fail(reason)
        return if self.closed?

        begin
            @raw_socket.write("HTTP/1.1 400 Bad Request\nContent-Type: text/plain\n\n" + reason + "\r\n\r\n")
        rescue Errno::EPIPE
        end
        @raw_socket.close()
        @status = Status::CLOSED
    end

    def close()
        return if @status == Status::CLOSED

        self.emit("close")
        @raw_socket.close()
        @status = Status::CLOSED
    end

    def test_closed()
        begin
            res = @raw_socket.recvfrom(2, Socket::MSG_PEEK)
            if res[0] == "" && res[1] == nil
                self.close()
                return true
            end
        rescue Errno::ECONNRESET, Errno::EPIPE
            self.close()
            return true
        end

        return false
    end

    def to_io
        return @raw_socket
    end
end

class WebSocketServer
    include Listenable

    def initialize(port)
        @server = TCPServer.new('0.0.0.0', port)
        @clients = []
    end

    def ensure_one_connection(socket)
        other_socket = @clients.find { |other_socket| socket.ip == other_socket.ip }
        other_socket.send_close() if other_socket
    end

    def start()
        while !@server.closed? do
            @clients.each do |client|
                client.close() if client.status != WebSocket::Status::OPEN
            end
            @clients = @clients.reject { |c| c.closed? }
            readable, _, _ = IO.select([@server, *@clients], nil, nil, 1)
            next unless readable

            readable.each do |socket|
                if socket == @server
                    websocket = WebSocket.new(@server.accept)
                    next if websocket.status != WebSocket::Status::OPEN
                    self.ensure_one_connection(websocket)
                    @clients.push(websocket)
                    self.emit_thread("connection", websocket)
                    next
                end

                next if socket.test_closed()

                socket.recv()
            end
        end

    end

    def start_nonblocking()
        Thread.new { self.start() }
    end
end
