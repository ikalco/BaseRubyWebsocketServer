require 'socket'
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

	attr_reader :sock_domain, :remote_port, :remote_hostname, :ip

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
		# Read the HTTP request. We know it's finished when we see a line with nothing but \r\n
		http_request = ''
		while (line = @raw_socket.gets()) && (line != "\r\n")
			http_request += line
		end

		# Grab the security key from the headers. If one isn't present, close the connection.
		if matches = http_request.match(/^Sec-WebSocket-Key: (\S+)/)
			websocket_key = matches[1]
		else
			self.close("Aborting non-websocket connection!")
			return
		end

		response_key = Digest::SHA1.base64digest([websocket_key, '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'].join)

		response = "HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Accept: #{response_key}\r\n\r\n"

		@raw_socket.write(response)

		if (!@raw_socket.closed?)
			@status = Status::OPEN
		else
			self.close("Connection Failed!")
		end
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

		if (is_masked == 1)
			mask_key = 4.times.map {  @raw_socket.getbyte() }
			maksed_data = payload_length.times.map {  @raw_socket.getbyte() }
			data = maksed_data.each_with_index.map { |byte, i| byte ^ mask_key[i % 4] }
		else
			self.close("Unmasked frame from client to server!")
		end

		return fin, opcode, is_masked, payload_length, data
	end

	def recv()
		return self.close() if self.closed?

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
			self.close("Control frame can't be fragmented") if (fin != 1)
			self.close("Control frame can't have payload length greater than 125") if (payload_length > 125)

			if (@status == Status::OPEN && payload_length > 0)
				status_code = data.pack("n")
				msg = data.drop(2).pack('C*').force_encoding('utf-8')

				self.close("Closing with Status Code of #{status_code}:\r\n#{msg}")
			else
				self.close()
			end
		when 9
			# ping frame
			self.close("Control frame can't be fragmented") if (fin != 1)
			self.close("Control frame can't have payload length greater than 125") if (payload_length > 125)

			# send pong frame
			if (@status == Status::OPEN)
				self.send(1, 9, 0, data)
			end
		when 10
			# pong frame
			self.close("Control frame can't be fragmented") if (fin != 1)
			self.close("Control frame can't have payload length greater than 125") if (payload_length > 125)

			# we don't care about pong frames, so do nothing
		else
			self.close("Unsupported Opcode!")
		end
	end

	def send_text(data)
		self.send(1, 1, 0, data)
	end

	def send_binary(data)
		self.send(1, 2, 0, data)
	end

	def send(fin, opcode, mask, data = [])
		return self.close() if self.closed?
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

	def close(reason = "")
		return if self.closed?

		Thread.new {
			@status = Status::CLOSING
			self.emit("close", reason)

			if (!@raw_socket.closed?)
				# send close websocket frame

				self.send(1, 8, 0)
				@raw_socket.close()
			end

			@status = Status::CLOSED
		}
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
		if (other_socket != nil)
			other_socket.close()
		end
		@clients.push(socket)
	end

	def start()
		while !@server.closed? do
			Thread.start(@server.accept) do |raw_socket|
				socket = WebSocket.new(raw_socket)

				self.ensure_one_connection(socket)

				recv_thread = Thread.new {
					Thread.stop()

					while !socket.closed? do
						socket.recv()
					end
				}
				sleep(0.1) while recv_thread.status != "sleep"

				socket.on("close") do
					recv_thread.exit()
				end

				self.emit_thread("connection", socket)

				recv_thread.run()
				recv_thread.join()
			end
		end
	end

	def start_nonblocking()
		return Thread.new { self.start() }
	end
end